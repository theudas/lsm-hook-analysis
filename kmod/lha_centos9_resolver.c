#include "lha_centos9_resolver.h"

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/string.h>

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
	umode_t mode = file_inode(file)->i_mode;
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

static int lha_fill_subject(struct lha_subject_v1 *subject)
{
	u32 secid = 0;
	char *secctx = NULL;
	u32 secctx_len = 0;
	int rc;

	memset(subject, 0, sizeof(*subject));
	subject->pid = task_tgid_nr(current);
	subject->tid = task_pid_nr(current);
	lha_copy_string(subject->comm, sizeof(subject->comm), current->comm);

	security_cred_getsecid(current_cred(), &secid);
	rc = security_secid_to_secctx(secid, &secctx, &secctx_len);
	if (rc)
		return rc;

	lha_copy_blob_string(subject->scontext, sizeof(subject->scontext),
			     secctx, secctx_len);
	security_release_secctx(secctx, secctx_len);
	return 0;
}

static void lha_fill_target_common(struct inode *inode, struct lha_target_v1 *target)
{
	memset(target, 0, sizeof(*target));
	lha_copy_string(target->dev, sizeof(target->dev), inode->i_sb->s_id);
	target->ino = inode->i_ino;
	lha_copy_string(target->type, sizeof(target->type),
			lha_mode_to_obj_type(inode->i_mode));
	lha_copy_string(target->tclass, sizeof(target->tclass),
			lha_mode_to_tclass(inode->i_mode));
}

static void lha_fill_fallback_name(const char *name, struct lha_target_v1 *target)
{
	if (name && name[0] != '\0')
		lha_copy_string(target->path, sizeof(target->path), name);
	else
		lha_copy_string(target->path, sizeof(target->path), "<unknown>");
}

static int lha_fill_target_path_from_file(struct file *file, struct lha_target_v1 *target)
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

static int lha_fill_target_path_from_inode(struct inode *inode, struct lha_target_v1 *target)
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

static int lha_fill_target_context(struct inode *inode, struct lha_target_v1 *target)
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

static int lha_fill_target_from_inode(struct inode *inode, struct lha_target_v1 *target)
{
	int rc;

	lha_fill_target_common(inode, target);
	rc = lha_fill_target_context(inode, target);
	if (rc)
		return rc;

	lha_fill_target_path_from_inode(inode, target);
	return 0;
}

static int lha_fill_target_from_file(struct file *file, struct lha_target_v1 *target)
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

static int lha_resolve_inode_permission(const struct lha_capture_event_v1 *in,
					struct lha_enriched_event_v1 *out)
{
	struct inode *inode = in->args.inode_permission.inode;

	lha_copy_string(out->hook, sizeof(out->hook), "selinux_inode_permission");
	lha_copy_string(out->hook_signature, sizeof(out->hook_signature),
			"static int selinux_inode_permission(struct inode *inode, int mask)");

	if (lha_fill_subject(&out->subject))
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

	if (lha_fill_subject(&out->subject))
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

	if (lha_fill_subject(&out->subject))
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
	if (!in || !out || in->version != 1)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->version = in->version;
	out->hook_id = in->hook_id;
	out->timestamp_ns = in->ts_ns;

	switch (in->hook_id) {
	case LHA_HOOK_INODE_PERMISSION:
		return lha_resolve_inode_permission(in, out);
	case LHA_HOOK_FILE_OPEN:
		return lha_resolve_file_open(in, out);
	case LHA_HOOK_FILE_PERMISSION:
		return lha_resolve_file_permission(in, out);
	default:
		return -EINVAL;
	}
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
MODULE_DESCRIPTION("CentOS Stream 9 SELinux hook resolver");
