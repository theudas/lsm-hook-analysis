#include "lha_centos9_resolver.h"

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#define LHA_AVC_CACHE_LEN 128

static DEFINE_SPINLOCK(lha_avc_cache_lock);
static struct lha_avc_event_v1 lha_avc_cache[LHA_AVC_CACHE_LEN];
static size_t lha_avc_cache_next;
static bool lha_avc_cache_debug;

module_param_named(debug_avc_cache, lha_avc_cache_debug, bool, 0644);
MODULE_PARM_DESC(debug_avc_cache,
		 "Log resolver AVC cache inserts and rejects for debugging");

static void lha_copy_string(char *dst, size_t dst_len, const char *src)
{
	if (dst_len == 0)
		return;

	if (!src) {
		dst[0] = '\0';
		return;
	}

	strscpy(dst, src, dst_len);
}

static void lha_copy_blob_string(char *dst, size_t dst_len,
				 const char *src, u32 src_len)
{
	size_t copy_len;

	if (dst_len == 0)
		return;

	if (!src || src_len == 0) {
		dst[0] = '\0';
		return;
	}

	copy_len = min_t(size_t, (size_t)src_len, dst_len - 1);
	if (copy_len > 0 && src[copy_len - 1] == '\0')
		copy_len--;

	memcpy(dst, src, copy_len);
	dst[copy_len] = '\0';
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

static void lha_append_perm(char *buf, size_t buf_len, const char *perm)
{
	size_t used;

	if (!buf || buf_len == 0 || !perm || perm[0] == '\0')
		return;

	used = strnlen(buf, buf_len);
	if (used >= buf_len - 1)
		return;

	if (used != 0) {
		buf[used++] = '|';
		buf[used] = '\0';
	}

	strscpy(buf + used, perm, buf_len - used);
}

static void lha_decode_mask_perm(umode_t mode, int mask, bool add_open,
				 char *buf, size_t buf_len)
{
	int eff = mask & (LHA_MAY_READ | LHA_MAY_WRITE |
			  LHA_MAY_EXEC | LHA_MAY_APPEND);

	if (!buf || buf_len == 0)
		return;

	buf[0] = '\0';
	if (add_open)
		lha_append_perm(buf, buf_len, "open");

	if (eff == 0)
		return;

	if (S_ISDIR(mode)) {
		if (eff & LHA_MAY_READ)
			lha_append_perm(buf, buf_len, "read");
		if (eff & LHA_MAY_WRITE)
			lha_append_perm(buf, buf_len, "write");
		if (eff & LHA_MAY_EXEC)
			lha_append_perm(buf, buf_len, "search");
		return;
	}

	if (eff & LHA_MAY_READ)
		lha_append_perm(buf, buf_len, "read");
	if (eff & LHA_MAY_EXEC)
		lha_append_perm(buf, buf_len, "exec");
	if (eff & LHA_MAY_APPEND)
		lha_append_perm(buf, buf_len, "append");
	else if (eff & LHA_MAY_WRITE)
		lha_append_perm(buf, buf_len, "write");
}

static void lha_decode_file_open_perm(const struct file *file,
				      char *buf, size_t buf_len)
{
#ifdef O_EXEC
	umode_t mode = file_inode(file)->i_mode;
#endif
	int accmode = file->f_flags & O_ACCMODE;

	if (!buf || buf_len == 0)
		return;

	buf[0] = '\0';
	lha_append_perm(buf, buf_len, "open");

	if (accmode == O_RDONLY || accmode == O_RDWR)
		lha_append_perm(buf, buf_len, "read");

	if (accmode == O_WRONLY || accmode == O_RDWR) {
		if (file->f_flags & O_APPEND)
			lha_append_perm(buf, buf_len, "append");
		else
			lha_append_perm(buf, buf_len, "write");
	}

#ifdef O_EXEC
	if (file->f_flags & O_EXEC)
		lha_append_perm(buf, buf_len, S_ISDIR(mode) ? "search" : "exec");
#endif
}

static void lha_classify_runtime_result(int ret, char *buf, size_t buf_len)
{
	if (ret == 0) {
		lha_copy_string(buf, buf_len, "allow");
		return;
	}
	if (ret == -EACCES) {
		lha_copy_string(buf, buf_len, "deny");
		return;
	}
	lha_copy_string(buf, buf_len, "error");
}

static bool lha_string_present(const char *text)
{
	return text && text[0] != '\0';
}

static u64 lha_absolute_diff(u64 a, u64 b)
{
	return a >= b ? a - b : b - a;
}

static bool lha_next_perm_token(const char **cursor, char *token, size_t token_len)
{
	size_t used = 0;

	if (!cursor || !*cursor || !token || token_len == 0)
		return false;

	while (**cursor == '|')
		++(*cursor);

	if (**cursor == '\0') {
		token[0] = '\0';
		return false;
	}

	while (**cursor != '\0' && **cursor != '|') {
		if (used + 1 < token_len)
			token[used++] = **cursor;
		++(*cursor);
	}

	token[used] = '\0';
	return used != 0;
}

static bool lha_perm_list_has_token(const char *perm_list, const char *needle)
{
	const char *cursor = perm_list;
	char token[LHA_MAX_PERM_LEN];

	if (!lha_string_present(perm_list) || !lha_string_present(needle))
		return false;

	while (lha_next_perm_token(&cursor, token, sizeof(token))) {
		if (strcmp(token, needle) == 0)
			return true;
	}

	return false;
}

static bool lha_perm_list_contains_all(const char *haystack, const char *needle)
{
	const char *cursor = needle;
	char token[LHA_MAX_PERM_LEN];

	if (!lha_string_present(haystack) || !lha_string_present(needle))
		return false;

	while (lha_next_perm_token(&cursor, token, sizeof(token))) {
		if (!lha_perm_list_has_token(haystack, token))
			return false;
	}

	return true;
}

static bool lha_perm_lists_match(const char *lhs, const char *rhs)
{
	if (!lha_string_present(lhs) || !lha_string_present(rhs))
		return false;

	return lha_perm_list_contains_all(lhs, rhs) ||
	       lha_perm_list_contains_all(rhs, lhs);
}

static bool lha_event_has_match_keys(const struct lha_enriched_event_v1 *event)
{
	return event &&
	       lha_string_present(event->subject.scontext) &&
	       lha_string_present(event->target.tcontext) &&
	       lha_string_present(event->target.tclass) &&
	       lha_string_present(event->request.perm);
}

static bool lha_avc_event_has_match_keys(const struct lha_avc_event_v1 *event)
{
	return event &&
	       event->denied != 0 &&
	       lha_string_present(event->scontext) &&
	       lha_string_present(event->tcontext) &&
	       lha_string_present(event->tclass) &&
	       lha_string_present(event->perm);
}

static int lha_candidate_score(const struct lha_enriched_event_v1 *event,
			       const struct lha_avc_event_v1 *avc)
{
	int score = 0;

	if (avc->tid != 0 && event->subject.tid != 0) {
		if (avc->tid != event->subject.tid)
			return -1;
		score += 4;
	}

	if (avc->pid != 0 && event->subject.pid != 0) {
		if (avc->pid != event->subject.pid)
			return -1;
		score += 2;
	}

	if (lha_string_present(avc->comm) && lha_string_present(event->subject.comm)) {
		if (strcmp(avc->comm, event->subject.comm) != 0)
			return -1;
		score += 1;
	}

	if (avc->permissive != 0)
		score += 1;

	return score;
}

static bool lha_primary_fields_match(const struct lha_enriched_event_v1 *event,
				     const struct lha_avc_event_v1 *avc,
				     u64 window_ns,
				     u64 *delta_ns)
{
	u64 delta;

	if (!lha_event_has_match_keys(event) || !lha_avc_event_has_match_keys(avc))
		return false;

	if (strcmp(event->subject.scontext, avc->scontext) != 0 ||
	    strcmp(event->target.tcontext, avc->tcontext) != 0 ||
	    strcmp(event->target.tclass, avc->tclass) != 0 ||
	    !lha_perm_lists_match(event->request.perm, avc->perm))
		return false;

	delta = lha_absolute_diff(event->timestamp_ns, avc->timestamp_ns);
	if (delta > window_ns)
		return false;

	if (delta_ns)
		*delta_ns = delta;
	return true;
}

static int lha_fill_subject(struct task_struct *task, const struct cred *cred,
			    struct lha_subject_v1 *subject)
{
	u32 secid = 0;
	char *secctx = NULL;
	u32 secctx_len = 0;
	int rc;

	if (!task || !cred)
		return -EINVAL;

	memset(subject, 0, sizeof(*subject));
	subject->pid = task_tgid_nr(task);
	subject->tid = task_pid_nr(task);
	lha_copy_string(subject->comm, sizeof(subject->comm), task->comm);

	security_cred_getsecid(cred, &secid);
	rc = security_secid_to_secctx(secid, &secctx, &secctx_len);
	if (rc)
		return rc;

	lha_copy_blob_string(subject->scontext, sizeof(subject->scontext),
			     secctx, secctx_len);
	security_release_secctx(secctx, secctx_len);
	return 0;
}

static void lha_fill_target_common(struct inode *inode,
				   struct lha_target_v1 *target)
{
	memset(target, 0, sizeof(*target));
	lha_copy_string(target->dev, sizeof(target->dev), inode->i_sb->s_id);
	target->ino = inode->i_ino;
	lha_copy_string(target->type, sizeof(target->type),
			lha_mode_to_obj_type(inode->i_mode));
	lha_copy_string(target->tclass, sizeof(target->tclass),
			lha_mode_to_tclass(inode->i_mode));
}

static void lha_fill_fallback_name(const char *name,
				   struct lha_target_v1 *target)
{
	if (name && name[0] != '\0')
		lha_copy_string(target->path, sizeof(target->path), name);
	else
		lha_copy_string(target->path, sizeof(target->path), "<unknown>");
}

static int lha_fill_target_path_from_file(struct file *file,
					  struct lha_target_v1 *target)
{
	char *tmp;
	char *resolved;

	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		lha_fill_fallback_name(file->f_path.dentry->d_name.name, target);
		return -ENOMEM;
	}

	resolved = d_path(&file->f_path, tmp, PATH_MAX);
	if (IS_ERR(resolved)) {
		kfree(tmp);
		lha_fill_fallback_name(file->f_path.dentry->d_name.name, target);
		return PTR_ERR(resolved);
	}

	lha_copy_string(target->path, sizeof(target->path), resolved);
	kfree(tmp);
	return 0;
}

static int lha_fill_target_path_from_inode(struct inode *inode,
					   struct lha_target_v1 *target)
{
	struct dentry *alias;
	char *tmp;
	char *resolved;

	alias = d_find_alias(inode);
	if (!alias) {
		lha_copy_string(target->path, sizeof(target->path), "<unknown>");
		return -ENOENT;
	}

	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		lha_fill_fallback_name(alias->d_name.name, target);
		dput(alias);
		return -ENOMEM;
	}

	resolved = dentry_path_raw(alias, tmp, PATH_MAX);
	if (IS_ERR(resolved)) {
		kfree(tmp);
		lha_fill_fallback_name(alias->d_name.name, target);
		dput(alias);
		return PTR_ERR(resolved);
	}

	lha_copy_string(target->path, sizeof(target->path), resolved);
	kfree(tmp);
	dput(alias);
	return 0;
}

static int lha_fill_target_context(struct inode *inode,
				   struct lha_target_v1 *target)
{
	void *ctx = NULL;
	u32 ctx_len = 0;
	int rc;

	rc = security_inode_getsecctx(inode, &ctx, &ctx_len);
	if (rc)
		return rc;

	lha_copy_blob_string(target->tcontext, sizeof(target->tcontext),
			     ctx, ctx_len);
	security_release_secctx((char *)ctx, ctx_len);
	return 0;
}

static int lha_fill_target_from_inode(struct inode *inode,
				      struct lha_target_v1 *target)
{
	int rc;

	lha_fill_target_common(inode, target);
	rc = lha_fill_target_context(inode, target);
	if (rc)
		return rc;

	lha_fill_target_path_from_inode(inode, target);
	return 0;
}

static int lha_fill_target_from_file(struct file *file,
				     struct lha_target_v1 *target)
{
	int rc;
	struct inode *inode = file_inode(file);

	lha_fill_target_common(inode, target);
	rc = lha_fill_target_context(inode, target);
	if (rc)
		return rc;

	lha_fill_target_path_from_file(file, target);
	return 0;
}

static void lha_fill_result(const struct lha_capture_event_v1 *in,
			    struct lha_result_v1 *result)
{
	memset(result, 0, sizeof(*result));
	result->ret = in->ret;
	lha_classify_runtime_result(in->ret,
				    result->runtime_result,
				    sizeof(result->runtime_result));
	lha_copy_string(result->policy_result,
			sizeof(result->policy_result),
			"unknown");
}

const char *lha_centos9_policy_result_kind_to_string(enum lha_policy_result_kind kind)
{
	switch (kind) {
	case LHA_POLICY_RESULT_DENY:
		return "deny";
	case LHA_POLICY_RESULT_INFERRED_ALLOW:
		return "inferred_allow";
	case LHA_POLICY_RESULT_ALLOW:
		return "allow";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(lha_centos9_policy_result_kind_to_string);

enum lha_policy_result_kind lha_centos9_correlate_avc_policy(
	const struct lha_enriched_event_v1 *event,
	const struct lha_avc_event_v1 *avc_events,
	size_t avc_count,
	const struct lha_avc_match_options *options)
{
	u64 window_ns = LHA_DEFAULT_AVC_WINDOW_NS;
	int best_score = -1;
	u64 best_delta = U64_MAX;
	bool ambiguous = false;
	bool matched = false;
	size_t i;

	if (options && options->window_ns != 0)
		window_ns = options->window_ns;

	if (!lha_event_has_match_keys(event))
		return LHA_POLICY_RESULT_UNKNOWN;
	if (avc_count != 0 && !avc_events)
		return LHA_POLICY_RESULT_UNKNOWN;

	for (i = 0; i < avc_count; ++i) {
		u64 delta = 0;
		int score;

		if (!lha_primary_fields_match(event, &avc_events[i], window_ns, &delta))
			continue;

		score = lha_candidate_score(event, &avc_events[i]);
		if (score < 0)
			continue;

		if (!matched || score > best_score ||
		    (score == best_score && delta < best_delta)) {
			matched = true;
			ambiguous = false;
			best_score = score;
			best_delta = delta;
			continue;
		}

		if (score == best_score && delta == best_delta)
			ambiguous = true;
	}

	if (matched)
		return ambiguous ? LHA_POLICY_RESULT_UNKNOWN : LHA_POLICY_RESULT_DENY;

	return LHA_POLICY_RESULT_INFERRED_ALLOW;
}
EXPORT_SYMBOL_GPL(lha_centos9_correlate_avc_policy);

int lha_centos9_apply_avc_policy_result(
	struct lha_enriched_event_v1 *event,
	const struct lha_avc_event_v1 *avc_events,
	size_t avc_count,
	const struct lha_avc_match_options *options)
{
	enum lha_policy_result_kind kind;

	if (!event)
		return -EINVAL;

	kind = lha_centos9_correlate_avc_policy(event, avc_events, avc_count,
						 options);
	lha_copy_string(event->result.policy_result,
			sizeof(event->result.policy_result),
			lha_centos9_policy_result_kind_to_string(kind));
	return 0;
}
EXPORT_SYMBOL_GPL(lha_centos9_apply_avc_policy_result);

int lha_centos9_record_avc_event(const struct lha_avc_event_v1 *event)
{
	unsigned long flags;
	size_t index;

	if (!event) {
		if (lha_avc_cache_debug)
			pr_warn("lha_centos9_resolver: reject avc cache insert: null event\n");
		return -EINVAL;
	}
	if (!lha_avc_event_has_match_keys(event)) {
		if (lha_avc_cache_debug)
			pr_warn("lha_centos9_resolver: reject avc cache insert: denied=%u tclass=%s perm=%s scontext=%s tcontext=%s\n",
				event->denied, event->tclass, event->perm,
				event->scontext, event->tcontext);
		return -EINVAL;
	}

	spin_lock_irqsave(&lha_avc_cache_lock, flags);
	index = lha_avc_cache_next++ % ARRAY_SIZE(lha_avc_cache);
	lha_avc_cache[index] = *event;
	spin_unlock_irqrestore(&lha_avc_cache_lock, flags);

	if (lha_avc_cache_debug)
		pr_info("lha_centos9_resolver: cached avc deny index=%zu pid=%u tid=%u comm=%s permissive=%u tclass=%s perm=%s scontext=%s tcontext=%s\n",
			index, event->pid, event->tid, event->comm, event->permissive,
			event->tclass, event->perm, event->scontext, event->tcontext);

	return 0;
}
EXPORT_SYMBOL_GPL(lha_centos9_record_avc_event);

static int lha_apply_cached_avc_policy_result(struct lha_enriched_event_v1 *event)
{
	struct lha_avc_match_options options = {
		.window_ns = LHA_DEFAULT_AVC_WINDOW_NS,
	};
	enum lha_policy_result_kind kind;
	unsigned long flags;

	if (!event)
		return -EINVAL;

	spin_lock_irqsave(&lha_avc_cache_lock, flags);
	kind = lha_centos9_correlate_avc_policy(event, lha_avc_cache,
						 ARRAY_SIZE(lha_avc_cache),
						 &options);
	spin_unlock_irqrestore(&lha_avc_cache_lock, flags);

	lha_copy_string(event->result.policy_result,
			sizeof(event->result.policy_result),
			lha_centos9_policy_result_kind_to_string(kind));
	return 0;
}

static int lha_resolve_inode_permission(const struct lha_capture_event_v1 *in,
					struct lha_enriched_event_v1 *out)
{
	struct inode *inode = in->args.inode_permission.inode;

	lha_copy_string(out->hook, sizeof(out->hook), "selinux_inode_permission");
	lha_copy_string(out->hook_signature, sizeof(out->hook_signature),
			"static int selinux_inode_permission(struct inode *inode, int mask)");

	if (lha_fill_subject(in->subject.task, in->subject.cred, &out->subject))
		return -EINVAL;
	if (lha_fill_target_from_inode(inode, &out->target))
		return -EINVAL;

	out->request.mask_raw = in->args.inode_permission.mask;
	lha_copy_string(out->request.obj_type, sizeof(out->request.obj_type),
			lha_mode_to_obj_type(inode->i_mode));
	lha_decode_mask_perm(inode->i_mode, in->args.inode_permission.mask,
			     in->args.inode_permission.mask & LHA_MAY_OPEN,
			     out->request.perm, sizeof(out->request.perm));
	lha_fill_result(in, &out->result);
	return 0;
}

static int lha_resolve_file_open(const struct lha_capture_event_v1 *in,
				 struct lha_enriched_event_v1 *out)
{
	struct file *file = in->args.file_open.file;
	struct inode *inode = file_inode(file);

	lha_copy_string(out->hook, sizeof(out->hook), "selinux_file_open");
	lha_copy_string(out->hook_signature, sizeof(out->hook_signature),
			"static int selinux_file_open(struct file *file)");

	if (lha_fill_subject(in->subject.task, in->subject.cred, &out->subject))
		return -EINVAL;
	if (lha_fill_target_from_file(file, &out->target))
		return -EINVAL;

	out->request.mask_raw = 0;
	lha_copy_string(out->request.obj_type, sizeof(out->request.obj_type),
			lha_mode_to_obj_type(inode->i_mode));
	lha_decode_file_open_perm(file, out->request.perm,
				  sizeof(out->request.perm));
	lha_fill_result(in, &out->result);
	return 0;
}

static int lha_resolve_file_permission(const struct lha_capture_event_v1 *in,
				       struct lha_enriched_event_v1 *out)
{
	struct file *file = in->args.file_permission.file;
	struct inode *inode = file_inode(file);
	int effective_mask = in->args.file_permission.mask;

	lha_copy_string(out->hook, sizeof(out->hook), "selinux_file_permission");
	lha_copy_string(out->hook_signature, sizeof(out->hook_signature),
			"static int selinux_file_permission(struct file *file, int mask)");

	if (lha_fill_subject(in->subject.task, in->subject.cred, &out->subject))
		return -EINVAL;
	if (lha_fill_target_from_file(file, &out->target))
		return -EINVAL;

	if ((file->f_flags & O_APPEND) && (effective_mask & LHA_MAY_WRITE))
		effective_mask |= LHA_MAY_APPEND;

	out->request.mask_raw = in->args.file_permission.mask;
	lha_copy_string(out->request.obj_type, sizeof(out->request.obj_type),
			lha_mode_to_obj_type(inode->i_mode));
	lha_decode_mask_perm(inode->i_mode, effective_mask, false,
			     out->request.perm, sizeof(out->request.perm));
	lha_fill_result(in, &out->result);
	return 0;
}

int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
			      struct lha_enriched_event_v1 *out)
{
	int rc;

	if (!in || !out || in->version != 1)
		return -EINVAL;
	if (!in->subject.task || !in->subject.cred)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->version = in->version;
	out->hook_id = in->hook_id;
	out->timestamp_ns = in->ts_ns;

	switch (in->hook_id) {
	case LHA_HOOK_INODE_PERMISSION:
		rc = lha_resolve_inode_permission(in, out);
		break;
	case LHA_HOOK_FILE_OPEN:
		rc = lha_resolve_file_open(in, out);
		break;
	case LHA_HOOK_FILE_PERMISSION:
		rc = lha_resolve_file_permission(in, out);
		break;
	default:
		return -EINVAL;
	}

	if (rc)
		return rc;

	return lha_apply_cached_avc_policy_result(out);
}
EXPORT_SYMBOL_GPL(lha_centos9_resolve_event);

static int lha_appendf(char *buf, size_t buf_len, size_t *off,
		       const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*off >= buf_len)
		return -ENOSPC;

	va_start(ap, fmt);
	n = vscnprintf(buf + *off, buf_len - *off, fmt, ap);
	va_end(ap);

	*off += n;
	return 0;
}

static int lha_append_json_string(char *buf, size_t buf_len, size_t *off,
				  const char *text)
{
	const unsigned char *p = (const unsigned char *)(text ? text : "");

	lha_appendf(buf, buf_len, off, "\"");
	while (*p != '\0') {
		switch (*p) {
		case '\\':
			lha_appendf(buf, buf_len, off, "\\\\");
			break;
		case '"':
			lha_appendf(buf, buf_len, off, "\\\"");
			break;
		case '\b':
			lha_appendf(buf, buf_len, off, "\\b");
			break;
		case '\f':
			lha_appendf(buf, buf_len, off, "\\f");
			break;
		case '\n':
			lha_appendf(buf, buf_len, off, "\\n");
			break;
		case '\r':
			lha_appendf(buf, buf_len, off, "\\r");
			break;
		case '\t':
			lha_appendf(buf, buf_len, off, "\\t");
			break;
		default:
			if (*p < 0x20)
				lha_appendf(buf, buf_len, off, "\\u%04x", *p);
			else
				lha_appendf(buf, buf_len, off, "%c", *p);
			break;
		}
		++p;
	}
	return lha_appendf(buf, buf_len, off, "\"");
}

int lha_centos9_format_json(const struct lha_enriched_event_v1 *event,
			    char *buf, size_t buf_len)
{
	size_t off = 0;

	if (!event || !buf || buf_len == 0)
		return -EINVAL;

	buf[0] = '\0';

	lha_appendf(buf, buf_len, &off, "{\n");
	lha_appendf(buf, buf_len, &off, "  \"hook\": ");
	lha_append_json_string(buf, buf_len, &off, event->hook);
	lha_appendf(buf, buf_len, &off, ",\n  \"hook_signature\": ");
	lha_append_json_string(buf, buf_len, &off, event->hook_signature);
	lha_appendf(buf, buf_len, &off, ",\n  \"timestamp_ns\": %llu,\n",
		    (unsigned long long)event->timestamp_ns);
	lha_appendf(buf, buf_len, &off, "  \"subject\": {\n");
	lha_appendf(buf, buf_len, &off, "    \"pid\": %u,\n", event->subject.pid);
	lha_appendf(buf, buf_len, &off, "    \"tid\": %u,\n", event->subject.tid);
	lha_appendf(buf, buf_len, &off, "    \"scontext\": ");
	lha_append_json_string(buf, buf_len, &off, event->subject.scontext);
	lha_appendf(buf, buf_len, &off, ",\n    \"comm\": ");
	lha_append_json_string(buf, buf_len, &off, event->subject.comm);
	lha_appendf(buf, buf_len, &off, "\n  },\n");
	lha_appendf(buf, buf_len, &off, "  \"request\": {\n");
	lha_appendf(buf, buf_len, &off, "    \"mask_raw\": %d,\n",
		    event->request.mask_raw);
	lha_appendf(buf, buf_len, &off, "    \"obj_type\": ");
	lha_append_json_string(buf, buf_len, &off, event->request.obj_type);
	lha_appendf(buf, buf_len, &off, ",\n    \"perm\": ");
	lha_append_json_string(buf, buf_len, &off, event->request.perm);
	lha_appendf(buf, buf_len, &off, "\n  },\n");
	lha_appendf(buf, buf_len, &off, "  \"target\": {\n");
	lha_appendf(buf, buf_len, &off, "    \"dev\": ");
	lha_append_json_string(buf, buf_len, &off, event->target.dev);
	lha_appendf(buf, buf_len, &off, ",\n    \"ino\": %llu,\n",
		    (unsigned long long)event->target.ino);
	lha_appendf(buf, buf_len, &off, "    \"type\": ");
	lha_append_json_string(buf, buf_len, &off, event->target.type);
	lha_appendf(buf, buf_len, &off, ",\n    \"path\": ");
	lha_append_json_string(buf, buf_len, &off, event->target.path);
	lha_appendf(buf, buf_len, &off, ",\n    \"tclass\": ");
	lha_append_json_string(buf, buf_len, &off, event->target.tclass);
	lha_appendf(buf, buf_len, &off, ",\n    \"tcontext\": ");
	lha_append_json_string(buf, buf_len, &off, event->target.tcontext);
	lha_appendf(buf, buf_len, &off, "\n  },\n");
	lha_appendf(buf, buf_len, &off, "  \"result\": {\n");
	lha_appendf(buf, buf_len, &off, "    \"ret\": %d,\n", event->result.ret);
	lha_appendf(buf, buf_len, &off, "    \"runtime_result\": ");
	lha_append_json_string(buf, buf_len, &off, event->result.runtime_result);
	lha_appendf(buf, buf_len, &off, ",\n    \"policy_result\": ");
	lha_append_json_string(buf, buf_len, &off, event->result.policy_result);
	lha_appendf(buf, buf_len, &off, "\n  }\n}\n");

	return 0;
}
EXPORT_SYMBOL_GPL(lha_centos9_format_json);

static int __init lha_centos9_resolver_init(void)
{
	pr_info("lha_centos9_resolver loaded\n");
	return 0;
}

static void __exit lha_centos9_resolver_exit(void)
{
	pr_info("lha_centos9_resolver unloaded\n");
}

module_init(lha_centos9_resolver_init);
module_exit(lha_centos9_resolver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI Codex");
MODULE_DESCRIPTION("CentOS Stream 9 production SELinux hook resolver");
