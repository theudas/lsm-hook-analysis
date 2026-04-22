// SPDX-License-Identifier: GPL-2.0
#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#define LHA_DEFAULT_MAX_EVENTS 1024
#define LHA_COMM_LEN TASK_COMM_LEN
#define LHA_HOOK_LEN 32
#define LHA_PHASE_LEN 16
#define LHA_TYPE_LEN 16
#define LHA_TCLASS_LEN 24
#define LHA_PERM_LEN 64
#define LHA_DEV_LEN 32
#define LHA_SECCTX_LEN 192
#define LHA_PATH_LEN 256
#define LHA_PATH_NOTE_LEN 64
#define LHA_RESULT_LEN 32

static unsigned int max_events = LHA_DEFAULT_MAX_EVENTS;
module_param(max_events, uint, 0644);
MODULE_PARM_DESC(max_events, "Maximum number of in-kernel records kept in the ring buffer");

static bool enabled = true;
module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable or disable probe capture");

enum lha_hook_id {
	LHA_HOOK_INODE_PERMISSION = 0,
	LHA_HOOK_FILE_OPEN,
	LHA_HOOK_FILE_PERMISSION,
};

struct lha_event_record {
	u64 seq;
	u64 ts_ns;
	u64 duration_ns;
	u32 tgid;
	u32 tid;
	u32 subject_secid;
	u32 mask_raw;
	u32 file_flags;
	u64 ino;
	int ret;
	char hook[LHA_HOOK_LEN];
	char phase[LHA_PHASE_LEN];
	char comm[LHA_COMM_LEN];
	char obj_type[LHA_TYPE_LEN];
	char perm[LHA_PERM_LEN];
	char dev[LHA_DEV_LEN];
	char tclass[LHA_TCLASS_LEN];
	char scontext[LHA_SECCTX_LEN];
	char tcontext[LHA_SECCTX_LEN];
	char path[LHA_PATH_LEN];
	char path_note[LHA_PATH_NOTE_LEN];
	char runtime_result[LHA_RESULT_LEN];
	char policy_result[LHA_RESULT_LEN];
};

struct lha_pending_work {
	struct work_struct work;
	enum lha_hook_id hook;
	u64 ts_enter_ns;
	u64 ts_exit_ns;
	u32 tgid;
	u32 tid;
	u32 subject_secid;
	u32 mask_raw;
	u32 file_flags;
	int ret;
	char comm[LHA_COMM_LEN];
	struct inode *inode;
	struct file *file;
};

struct lha_probe_ctx {
	struct lha_pending_work *pending;
};

struct lha_event_ring {
	struct lha_event_record *records;
	u64 head;
	u32 count;
	struct mutex lock;
};

static struct dentry *lha_debugfs_root;
static struct workqueue_struct *lha_wq;
static struct lha_event_ring lha_ring;
static atomic64_t lha_seq = ATOMIC64_INIT(0);
static atomic64_t queued_events = ATOMIC64_INIT(0);
static atomic64_t stored_events = ATOMIC64_INIT(0);
static atomic64_t dropped_events = ATOMIC64_INIT(0);

static const char *const lha_hook_names[] = {
	[LHA_HOOK_INODE_PERMISSION] = "selinux_inode_permission",
	[LHA_HOOK_FILE_OPEN] = "selinux_file_open",
	[LHA_HOOK_FILE_PERMISSION] = "selinux_file_permission",
};

static inline bool lha_capture_enabled(void)
{
	return READ_ONCE(enabled);
}

static void lha_copy_string(char *dst, size_t dst_len, const char *src)
{
	size_t i;

	if (!dst_len)
		return;

	if (!src) {
		strscpy(dst, "unknown", dst_len);
		return;
	}

	for (i = 0; i + 1 < dst_len && src[i]; i++) {
		unsigned char c = src[i];

		if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t')
			dst[i] = '_';
		else if (c < 0x20)
			dst[i] = '?';
		else
			dst[i] = c;
	}

	dst[i] = '\0';
}

static void lha_copy_ctx(char *dst, size_t dst_len, const char *src, u32 src_len)
{
	size_t len;
	char *tmp;

	if (!dst_len)
		return;

	if (!src || !src_len) {
		strscpy(dst, "unknown", dst_len);
		return;
	}

	len = min_t(size_t, src_len, dst_len - 1);
	if (len && src[len - 1] == '\0')
		len--;

	tmp = kmalloc(len + 1, GFP_KERNEL);
	if (!tmp) {
		strscpy(dst, "oom", dst_len);
		return;
	}

	memcpy(tmp, src, len);
	tmp[len] = '\0';
	lha_copy_string(dst, dst_len, tmp);
	kfree(tmp);
}

static const char *lha_mode_to_obj_type(umode_t mode)
{
	if (S_ISREG(mode))
		return "reg";
	if (S_ISDIR(mode))
		return "dir";
	if (S_ISLNK(mode))
		return "lnk";
	if (S_ISCHR(mode))
		return "chr";
	if (S_ISBLK(mode))
		return "blk";
	if (S_ISFIFO(mode))
		return "fifo";
	if (S_ISSOCK(mode))
		return "sock";
	return "unknown";
}

static const char *lha_mode_to_tclass(umode_t mode)
{
	if (S_ISREG(mode))
		return "file";
	if (S_ISDIR(mode))
		return "dir";
	if (S_ISLNK(mode))
		return "lnk_file";
	if (S_ISCHR(mode))
		return "chr_file";
	if (S_ISBLK(mode))
		return "blk_file";
	if (S_ISFIFO(mode))
		return "fifo_file";
	if (S_ISSOCK(mode))
		return "sock_file";
	return "unknown";
}

static void lha_append_perm(char *buf, size_t buflen, const char *perm)
{
	if (!perm || !buf || !buflen)
		return;

	if (buf[0])
		strlcat(buf, ",", buflen);
	strlcat(buf, perm, buflen);
}

static void lha_decode_mask_perms(umode_t mode, u32 mask, bool add_open,
				  char *buf, size_t buflen)
{
	u32 eff = mask & (MAY_READ | MAY_WRITE | MAY_EXEC | MAY_APPEND);

	buf[0] = '\0';

	if (add_open)
		lha_append_perm(buf, buflen, "open");

	if (!eff) {
		if (!buf[0])
			lha_append_perm(buf, buflen, "none");
		return;
	}

	if (S_ISDIR(mode)) {
		if (eff & MAY_READ)
			lha_append_perm(buf, buflen, "read");
		if (eff & MAY_WRITE)
			lha_append_perm(buf, buflen, "write");
		if (eff & MAY_EXEC)
			lha_append_perm(buf, buflen, "search");
	} else {
		if (eff & MAY_READ)
			lha_append_perm(buf, buflen, "read");
		if (eff & MAY_EXEC)
			lha_append_perm(buf, buflen, "exec");
		if (eff & MAY_APPEND)
			lha_append_perm(buf, buflen, "append");
		else if (eff & MAY_WRITE)
			lha_append_perm(buf, buflen, "write");
	}
}

static void lha_decode_open_perms(struct file *file, char *buf, size_t buflen)
{
	struct inode *inode = file_inode(file);
	bool is_dir = inode && S_ISDIR(inode->i_mode);

	buf[0] = '\0';
	lha_append_perm(buf, buflen, "open");

	if (file->f_mode & FMODE_READ)
		lha_append_perm(buf, buflen, "read");

	if (file->f_mode & FMODE_WRITE) {
		if (file->f_flags & O_APPEND)
			lha_append_perm(buf, buflen, "append");
		else
			lha_append_perm(buf, buflen, "write");
	}

	if (file->f_mode & FMODE_EXEC)
		lha_append_perm(buf, buflen, is_dir ? "search" : "exec");
}

static const char *lha_classify_inode_phase(struct inode *inode, u32 mask)
{
	u32 eff = mask & (MAY_READ | MAY_WRITE | MAY_EXEC | MAY_APPEND);

	if (mask & MAY_OPEN)
		return "open";

	if (inode && S_ISDIR(inode->i_mode) && eff == MAY_EXEC)
		return "path_walk";

	return "inode";
}

static void lha_classify_result(int ret, char *runtime, size_t runtime_len,
				char *policy, size_t policy_len)
{
	if (ret == 0) {
		strscpy(runtime, "allow", runtime_len);
		strscpy(policy, "unknown_if_permissive", policy_len);
		return;
	}

	if (ret == -EACCES) {
		strscpy(runtime, "deny", runtime_len);
		strscpy(policy, "deny", policy_len);
		return;
	}

	if (ret == -ECHILD) {
		strscpy(runtime, "error", runtime_len);
		strscpy(policy, "special_echild", policy_len);
		return;
	}

	strscpy(runtime, "error", runtime_len);
	strscpy(policy, "unknown", policy_len);
}

static void lha_resolve_subject_context(struct lha_event_record *rec)
{
	char *ctx = NULL;
	u32 ctx_len = 0;
	int rc;

	rc = security_secid_to_secctx(rec->subject_secid, &ctx, &ctx_len);
	if (rc || !ctx) {
		strscpy(rec->scontext, "unknown", sizeof(rec->scontext));
		return;
	}

	lha_copy_ctx(rec->scontext, sizeof(rec->scontext), ctx, ctx_len);
	security_release_secctx(ctx, ctx_len);
}

static void lha_resolve_inode_target(struct inode *inode, struct lha_event_record *rec)
{
	void *ctx = NULL;
	u32 ctx_len = 0;
	int rc;

	if (!inode) {
		strscpy(rec->dev, "unknown", sizeof(rec->dev));
		strscpy(rec->obj_type, "unknown", sizeof(rec->obj_type));
		strscpy(rec->tclass, "unknown", sizeof(rec->tclass));
		strscpy(rec->tcontext, "unknown", sizeof(rec->tcontext));
		rec->ino = 0;
		return;
	}

	lha_copy_string(rec->dev, sizeof(rec->dev), inode->i_sb->s_id);
	lha_copy_string(rec->obj_type, sizeof(rec->obj_type),
			lha_mode_to_obj_type(inode->i_mode));
	lha_copy_string(rec->tclass, sizeof(rec->tclass),
			lha_mode_to_tclass(inode->i_mode));
	rec->ino = inode->i_ino;

	rc = security_inode_getsecctx(inode, &ctx, &ctx_len);
	if (rc || !ctx) {
		strscpy(rec->tcontext, "unknown", sizeof(rec->tcontext));
		return;
	}

	lha_copy_ctx(rec->tcontext, sizeof(rec->tcontext), ctx, ctx_len);
	security_release_secctx(ctx, ctx_len);
}

static void lha_resolve_file_path(struct file *file, struct lha_event_record *rec)
{
	char *buf;
	char *path;

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf) {
		strscpy(rec->path, "unknown", sizeof(rec->path));
		strscpy(rec->path_note, "oom", sizeof(rec->path_note));
		return;
	}

	path = d_path(&file->f_path, buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		strscpy(rec->path, "unknown", sizeof(rec->path));
		strscpy(rec->path_note, "file_path_unavailable",
			sizeof(rec->path_note));
		free_page((unsigned long)buf);
		return;
	}

	lha_copy_string(rec->path, sizeof(rec->path), path);
	strscpy(rec->path_note, "file->f_path", sizeof(rec->path_note));
	free_page((unsigned long)buf);
}

static void lha_resolve_inode_alias_path(struct inode *inode, struct lha_event_record *rec)
{
	struct dentry *alias;
	char *buf;
	char *path;

	if (!inode) {
		strscpy(rec->path, "unknown", sizeof(rec->path));
		strscpy(rec->path_note, "no_inode", sizeof(rec->path_note));
		return;
	}

	alias = d_find_alias(inode);
	if (!alias) {
		strscpy(rec->path, "unknown", sizeof(rec->path));
		strscpy(rec->path_note, "inode_only_no_alias",
			sizeof(rec->path_note));
		return;
	}

	buf = (char *)__get_free_page(GFP_KERNEL);
	if (!buf) {
		dput(alias);
		strscpy(rec->path, "unknown", sizeof(rec->path));
		strscpy(rec->path_note, "oom", sizeof(rec->path_note));
		return;
	}

	path = dentry_path_raw(alias, buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		strscpy(rec->path, "unknown", sizeof(rec->path));
		strscpy(rec->path_note, "alias_path_unavailable",
			sizeof(rec->path_note));
	} else {
		lha_copy_string(rec->path, sizeof(rec->path), path);
		strscpy(rec->path_note, "alias_path_non_unique",
			sizeof(rec->path_note));
	}

	free_page((unsigned long)buf);
	dput(alias);
}

static void lha_store_record(const struct lha_event_record *rec)
{
	u32 idx;

	mutex_lock(&lha_ring.lock);

	idx = lha_ring.head % max_events;
	lha_ring.records[idx] = *rec;
	lha_ring.head++;
	if (lha_ring.count < max_events)
		lha_ring.count++;

	mutex_unlock(&lha_ring.lock);
	atomic64_inc(&stored_events);
}

static void lha_release_pending(struct lha_pending_work *pending)
{
	if (!pending)
		return;

	if (pending->file)
		fput(pending->file);
	if (pending->inode)
		iput(pending->inode);

	kfree(pending);
}

static void lha_event_worker(struct work_struct *work)
{
	struct lha_pending_work *pending =
		container_of(work, struct lha_pending_work, work);
	struct lha_event_record rec = {};
	struct inode *inode = pending->inode;

	if (!lha_capture_enabled())
		goto out;

	rec.seq = atomic64_inc_return(&lha_seq);
	rec.ts_ns = pending->ts_exit_ns;
	rec.duration_ns = pending->ts_exit_ns - pending->ts_enter_ns;
	rec.tgid = pending->tgid;
	rec.tid = pending->tid;
	rec.subject_secid = pending->subject_secid;
	rec.mask_raw = pending->mask_raw;
	rec.file_flags = pending->file_flags;
	rec.ret = pending->ret;

	lha_copy_string(rec.hook, sizeof(rec.hook),
			lha_hook_names[pending->hook]);
	lha_copy_string(rec.comm, sizeof(rec.comm), pending->comm);

	switch (pending->hook) {
	case LHA_HOOK_INODE_PERMISSION:
		lha_copy_string(rec.phase, sizeof(rec.phase),
				lha_classify_inode_phase(inode, pending->mask_raw));
		if (inode)
			lha_decode_mask_perms(inode->i_mode, pending->mask_raw,
					      pending->mask_raw & MAY_OPEN,
					      rec.perm, sizeof(rec.perm));
		else
			strscpy(rec.perm, "unknown", sizeof(rec.perm));
		lha_resolve_inode_target(inode, &rec);
		lha_resolve_inode_alias_path(inode, &rec);
		break;
	case LHA_HOOK_FILE_OPEN:
		lha_copy_string(rec.phase, sizeof(rec.phase), "open");
		if (pending->file) {
			inode = file_inode(pending->file);
			lha_decode_open_perms(pending->file, rec.perm,
					      sizeof(rec.perm));
			lha_resolve_inode_target(inode, &rec);
			lha_resolve_file_path(pending->file, &rec);
		}
		break;
	case LHA_HOOK_FILE_PERMISSION:
		lha_copy_string(rec.phase, sizeof(rec.phase), "io");
		if (pending->file) {
			inode = file_inode(pending->file);
			if ((pending->file->f_flags & O_APPEND) &&
			    (pending->mask_raw & MAY_WRITE))
				pending->mask_raw |= MAY_APPEND;
			lha_decode_mask_perms(inode ? inode->i_mode : 0,
					      pending->mask_raw, false,
					      rec.perm, sizeof(rec.perm));
			lha_resolve_inode_target(inode, &rec);
			lha_resolve_file_path(pending->file, &rec);
		}
		break;
	}

	if (!rec.perm[0])
		strscpy(rec.perm, "unknown", sizeof(rec.perm));
	if (!rec.path[0])
		strscpy(rec.path, "unknown", sizeof(rec.path));
	if (!rec.path_note[0])
		strscpy(rec.path_note, "unknown", sizeof(rec.path_note));

	lha_resolve_subject_context(&rec);
	lha_classify_result(rec.ret, rec.runtime_result, sizeof(rec.runtime_result),
			    rec.policy_result, sizeof(rec.policy_result));
	lha_store_record(&rec);

out:
	lha_release_pending(pending);
}

static struct lha_pending_work *lha_alloc_pending(enum lha_hook_id hook)
{
	struct lha_pending_work *pending;

	if (!lha_capture_enabled())
		return NULL;

	pending = kzalloc(sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		atomic64_inc(&dropped_events);
		return NULL;
	}

	INIT_WORK(&pending->work, lha_event_worker);
	pending->hook = hook;
	pending->ts_enter_ns = ktime_get_ns();
	pending->tgid = task_tgid_nr(current);
	pending->tid = task_pid_nr(current);
	get_task_comm(pending->comm, current);
	security_current_getsecid_subj(&pending->subject_secid);

	return pending;
}

static int lha_inode_permission_entry(struct kretprobe_instance *ri,
				      struct pt_regs *regs)
{
	struct lha_probe_ctx *ctx = (struct lha_probe_ctx *)ri->data;
	struct lha_pending_work *pending;
	struct inode *inode;

	pending = lha_alloc_pending(LHA_HOOK_INODE_PERMISSION);
	ctx->pending = pending;
	if (!pending)
		return 0;

	inode = (struct inode *)regs_get_kernel_argument(regs, 0);
	pending->mask_raw = (u32)regs_get_kernel_argument(regs, 1);
	if (inode) {
		ihold(inode);
		pending->inode = inode;
	}

	return 0;
}

static int lha_file_open_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct lha_probe_ctx *ctx = (struct lha_probe_ctx *)ri->data;
	struct lha_pending_work *pending;
	struct file *file;

	pending = lha_alloc_pending(LHA_HOOK_FILE_OPEN);
	ctx->pending = pending;
	if (!pending)
		return 0;

	file = (struct file *)regs_get_kernel_argument(regs, 0);
	if (file) {
		get_file(file);
		pending->file = file;
		pending->file_flags = file->f_flags;
	}

	return 0;
}

static int lha_file_permission_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct lha_probe_ctx *ctx = (struct lha_probe_ctx *)ri->data;
	struct lha_pending_work *pending;
	struct file *file;

	pending = lha_alloc_pending(LHA_HOOK_FILE_PERMISSION);
	ctx->pending = pending;
	if (!pending)
		return 0;

	file = (struct file *)regs_get_kernel_argument(regs, 0);
	pending->mask_raw = (u32)regs_get_kernel_argument(regs, 1);
	if (file) {
		get_file(file);
		pending->file = file;
		pending->file_flags = file->f_flags;
	}

	return 0;
}

static int lha_common_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct lha_probe_ctx *ctx = (struct lha_probe_ctx *)ri->data;
	struct lha_pending_work *pending = ctx->pending;

	if (!pending)
		return 0;

	pending->ret = (int)regs_return_value(regs);
	pending->ts_exit_ns = ktime_get_ns();
	atomic64_inc(&queued_events);

	if (!queue_work(lha_wq, &pending->work))
		atomic64_inc(&dropped_events);

	ctx->pending = NULL;
	return 0;
}

static struct kretprobe lha_inode_permission_probe = {
	.kp.symbol_name = "selinux_inode_permission",
	.entry_handler = lha_inode_permission_entry,
	.handler = lha_common_return,
	.data_size = sizeof(struct lha_probe_ctx),
	.maxactive = 64,
};

static struct kretprobe lha_file_open_probe = {
	.kp.symbol_name = "selinux_file_open",
	.entry_handler = lha_file_open_entry,
	.handler = lha_common_return,
	.data_size = sizeof(struct lha_probe_ctx),
	.maxactive = 64,
};

static struct kretprobe lha_file_permission_probe = {
	.kp.symbol_name = "selinux_file_permission",
	.entry_handler = lha_file_permission_entry,
	.handler = lha_common_return,
	.data_size = sizeof(struct lha_probe_ctx),
	.maxactive = 128,
};

static int lha_events_show(struct seq_file *m, void *unused)
{
	u64 start;
	u32 i;

	mutex_lock(&lha_ring.lock);

	start = lha_ring.head - lha_ring.count;
	for (i = 0; i < lha_ring.count; i++) {
		struct lha_event_record *rec;
		u32 idx = (start + i) % max_events;

		rec = &lha_ring.records[idx];
		seq_printf(m,
			   "{\"seq\":%llu,\"ts_ns\":%llu,\"duration_ns\":%llu,"
			   "\"subject\":{\"tgid\":%u,\"tid\":%u,\"comm\":\"%s\","
			   "\"secid\":%u,\"scontext\":\"%s\"},"
			   "\"request\":{\"hook\":\"%s\",\"phase\":\"%s\","
			   "\"mask_raw\":%u,\"file_flags\":%u,\"perm\":\"%s\"},"
			   "\"target\":{\"dev\":\"%s\",\"ino\":%llu,"
			   "\"type\":\"%s\",\"tclass\":\"%s\","
			   "\"tcontext\":\"%s\"},"
			   "\"path\":{\"path\":\"%s\",\"note\":\"%s\"},"
			   "\"result\":{\"ret\":%d,\"runtime_result\":\"%s\","
			   "\"policy_result\":\"%s\"}}\n",
			   (unsigned long long)rec->seq,
			   (unsigned long long)rec->ts_ns,
			   (unsigned long long)rec->duration_ns,
			   rec->tgid, rec->tid, rec->comm, rec->subject_secid,
			   rec->scontext, rec->hook, rec->phase, rec->mask_raw,
			   rec->file_flags, rec->perm, rec->dev,
			   (unsigned long long)rec->ino,
			   rec->obj_type, rec->tclass, rec->tcontext,
			   rec->path, rec->path_note, rec->ret,
			   rec->runtime_result, rec->policy_result);
	}

	mutex_unlock(&lha_ring.lock);
	return 0;
}

static int lha_stats_show(struct seq_file *m, void *unused)
{
	seq_printf(m,
		   "enabled=%u\n"
		   "max_events=%u\n"
		   "current_events=%u\n"
		   "head=%llu\n"
		   "queued_events=%llu\n"
		   "stored_events=%llu\n"
		   "dropped_events=%llu\n"
		   "inode_permission_nmissed=%d\n"
		   "file_open_nmissed=%d\n"
		   "file_permission_nmissed=%d\n",
		   lha_capture_enabled(), max_events, lha_ring.count,
		   (unsigned long long)lha_ring.head,
		   (unsigned long long)atomic64_read(&queued_events),
		   (unsigned long long)atomic64_read(&stored_events),
		   (unsigned long long)atomic64_read(&dropped_events),
		   lha_inode_permission_probe.nmissed,
		   lha_file_open_probe.nmissed,
		   lha_file_permission_probe.nmissed);
	return 0;
}

static ssize_t lha_control_write(struct file *file, const char __user *buf,
				 size_t len, loff_t *ppos)
{
	char cmd[32];

	if (!len)
		return 0;

	if (len >= sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = '\0';

	if (!strncmp(cmd, "clear", 5)) {
		mutex_lock(&lha_ring.lock);
		memset(lha_ring.records, 0,
		       sizeof(*lha_ring.records) * max_events);
		lha_ring.count = 0;
		lha_ring.head = 0;
		mutex_unlock(&lha_ring.lock);
		return len;
	}

	if (!strncmp(cmd, "enable=1", 8)) {
		WRITE_ONCE(enabled, true);
		return len;
	}

	if (!strncmp(cmd, "enable=0", 8)) {
		WRITE_ONCE(enabled, false);
		return len;
	}

	return -EINVAL;
}

DEFINE_SHOW_ATTRIBUTE(lha_events);
DEFINE_SHOW_ATTRIBUTE(lha_stats);

static const struct file_operations lha_control_fops = {
	.owner = THIS_MODULE,
	.write = lha_control_write,
	.llseek = no_llseek,
};

static int lha_register_probes(void)
{
	int rc;

	rc = register_kretprobe(&lha_file_open_probe);
	if (rc) {
		pr_err("lsm_hook_analysis: register_kretprobe(selinux_file_open) failed: %d\n",
		       rc);
		return rc;
	}

	return 0;
}

static void lha_unregister_probes(void)
{
	unregister_kretprobe(&lha_file_open_probe);
}

static int __init lha_init(void)
{
	int rc;

	if (!max_events)
		return -EINVAL;

	mutex_init(&lha_ring.lock);
	lha_ring.records = kcalloc(max_events, sizeof(*lha_ring.records),
				   GFP_KERNEL);
	if (!lha_ring.records)
		return -ENOMEM;

	lha_wq = alloc_workqueue("lsm_hook_analysis", WQ_UNBOUND | WQ_MEM_RECLAIM,
				 0);
	if (!lha_wq) {
		kfree(lha_ring.records);
		return -ENOMEM;
	}

	rc = lha_register_probes();
	if (rc)
		goto err_probes;

	lha_debugfs_root = debugfs_create_dir("lsm_hook_analysis", NULL);
	if (IS_ERR_OR_NULL(lha_debugfs_root)) {
		rc = lha_debugfs_root ? PTR_ERR(lha_debugfs_root) : -ENOMEM;
		goto err_debugfs;
	}

	debugfs_create_file("events", 0444, lha_debugfs_root, NULL,
			    &lha_events_fops);
	debugfs_create_file("stats", 0444, lha_debugfs_root, NULL,
			    &lha_stats_fops);
	debugfs_create_file("control", 0200, lha_debugfs_root, NULL,
			    &lha_control_fops);

	pr_info("lsm_hook_analysis: loaded, max_events=%u\n", max_events);
	return 0;

err_debugfs:
	lha_unregister_probes();
err_probes:
	destroy_workqueue(lha_wq);
	kfree(lha_ring.records);
	return rc;
}

static void __exit lha_exit(void)
{
	WRITE_ONCE(enabled, false);
	lha_unregister_probes();
	if (lha_wq) {
		flush_workqueue(lha_wq);
		destroy_workqueue(lha_wq);
	}
	debugfs_remove_recursive(lha_debugfs_root);
	kfree(lha_ring.records);
	pr_info("lsm_hook_analysis: unloaded\n");
}

module_init(lha_init);
module_exit(lha_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI Codex");
MODULE_DESCRIPTION("Out-of-tree SELinux hook analysis collector for CentOS Stream 9");
