#include "lha_resolver.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static void copy_string(char *dst, size_t dst_len, const char *src)
{
    if (dst_len == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_len, "%s", src);
}

static const char *mode_to_obj_type(uint32_t mode)
{
    if (S_ISREG(mode)) {
        return "reg";
    }
    if (S_ISDIR(mode)) {
        return "dir";
    }
    if (S_ISLNK(mode)) {
        return "lnk";
    }
    if (S_ISCHR(mode)) {
        return "chr";
    }
    if (S_ISBLK(mode)) {
        return "blk";
    }
    if (S_ISFIFO(mode)) {
        return "fifo";
    }
    if (S_ISSOCK(mode)) {
        return "sock";
    }
    return "unknown";
}

static const char *mode_to_tclass(uint32_t mode)
{
    if (S_ISREG(mode)) {
        return "file";
    }
    if (S_ISDIR(mode)) {
        return "dir";
    }
    if (S_ISLNK(mode)) {
        return "lnk_file";
    }
    if (S_ISCHR(mode)) {
        return "chr_file";
    }
    if (S_ISBLK(mode)) {
        return "blk_file";
    }
    if (S_ISFIFO(mode)) {
        return "fifo_file";
    }
    if (S_ISSOCK(mode)) {
        return "sock_file";
    }
    return "unknown";
}

static void append_perm(char *buf, size_t buf_len, const char *perm)
{
    size_t used;

    if (buf_len == 0 || perm == NULL || perm[0] == '\0') {
        return;
    }

    used = strlen(buf);
    if (used != 0 && used < buf_len - 1) {
        buf[used++] = '|';
        buf[used] = '\0';
    }

    if (used < buf_len - 1) {
        snprintf(buf + used, buf_len - used, "%s", perm);
    }
}

static void decode_mask_perm(uint32_t mode, int mask, bool add_open, char *buf, size_t buf_len)
{
    int eff = mask & (LHA_MAY_READ | LHA_MAY_WRITE | LHA_MAY_EXEC | LHA_MAY_APPEND);

    if (buf_len == 0) {
        return;
    }

    buf[0] = '\0';
    if (add_open) {
        append_perm(buf, buf_len, "open");
    }

    if (eff == 0) {
        return;
    }

    if (S_ISDIR(mode)) {
        if ((eff & LHA_MAY_READ) != 0) {
            append_perm(buf, buf_len, "read");
        }
        if ((eff & LHA_MAY_WRITE) != 0) {
            append_perm(buf, buf_len, "write");
        }
        if ((eff & LHA_MAY_EXEC) != 0) {
            append_perm(buf, buf_len, "search");
        }
        return;
    }

    if ((eff & LHA_MAY_READ) != 0) {
        append_perm(buf, buf_len, "read");
    }
    if ((eff & LHA_MAY_EXEC) != 0) {
        append_perm(buf, buf_len, "exec");
    }
    if ((eff & LHA_MAY_APPEND) != 0) {
        append_perm(buf, buf_len, "append");
    } else if ((eff & LHA_MAY_WRITE) != 0) {
        append_perm(buf, buf_len, "write");
    }
}

static void decode_file_open_perm(const struct lha_file_raw *file, char *buf, size_t buf_len)
{
    if (buf_len == 0) {
        return;
    }

    buf[0] = '\0';
    append_perm(buf, buf_len, "open");

    if ((file->f_mode & LHA_FILE_MODE_READ) != 0) {
        append_perm(buf, buf_len, "read");
    }
    if ((file->f_mode & LHA_FILE_MODE_WRITE) != 0) {
        if ((file->f_flags & O_APPEND) != 0) {
            append_perm(buf, buf_len, "append");
        } else {
            append_perm(buf, buf_len, "write");
        }
    }
    if ((file->f_mode & LHA_FILE_MODE_EXEC) != 0) {
        append_perm(buf, buf_len, S_ISDIR(file->inode.mode) ? "search" : "exec");
    }
}

static void classify_runtime_result(int ret, char *buf, size_t buf_len)
{
    if (ret == 0) {
        copy_string(buf, buf_len, "allow");
        return;
    }
    if (ret == -EACCES) {
        copy_string(buf, buf_len, "deny");
        return;
    }
    copy_string(buf, buf_len, "error");
}

static int resolve_policy_result(const struct lha_kernel_ops *ops,
                                 const struct lha_capture_event_v1 *event,
                                 struct lha_result_v1 *result)
{
    if (ops == NULL || ops->resolve_policy_result == NULL) {
        copy_string(result->policy_result, sizeof(result->policy_result), "unknown");
        return 0;
    }

    if (ops->resolve_policy_result(event, result->policy_result,
                                   sizeof(result->policy_result)) != 0 ||
        result->policy_result[0] == '\0') {
        copy_string(result->policy_result, sizeof(result->policy_result), "unknown");
    }
    return 0;
}

static int fill_subject(const struct lha_kernel_ops *ops,
                        const struct lha_capture_event_v1 *event,
                        uint64_t ts_ns,
                        struct lha_subject_v1 *subject)
{
    struct lha_subject_raw raw;

    if (ops == NULL || event == NULL || ops->resolve_subject == NULL ||
        ops->sid_to_context == NULL || subject == NULL ||
        event->subject.task == NULL || event->subject.cred == NULL) {
        return -EINVAL;
    }

    memset(&raw, 0, sizeof(raw));
    memset(subject, 0, sizeof(*subject));

    if (ops->resolve_subject(event->subject.task, event->subject.cred, ts_ns, &raw) != 0) {
        return -EINVAL;
    }
    if (ops->sid_to_context(raw.sid, subject->scontext, sizeof(subject->scontext)) != 0) {
        return -EINVAL;
    }

    subject->pid = raw.pid;
    subject->tid = raw.tid;
    copy_string(subject->comm, sizeof(subject->comm), raw.comm);
    return 0;
}

static int fill_target_from_inode_raw(const struct lha_kernel_ops *ops,
                                      const struct lha_inode_raw *raw,
                                      struct lha_target_v1 *target)
{
    if (ops == NULL || raw == NULL || target == NULL || ops->sid_to_context == NULL) {
        return -EINVAL;
    }

    memset(target, 0, sizeof(*target));
    copy_string(target->dev, sizeof(target->dev), raw->dev);
    target->ino = raw->ino;
    copy_string(target->type, sizeof(target->type), mode_to_obj_type(raw->mode));
    copy_string(target->path, sizeof(target->path), raw->path);

    if (ops->sclass_to_string != NULL &&
        ops->sclass_to_string(raw->sclass, target->tclass, sizeof(target->tclass)) == 0 &&
        target->tclass[0] != '\0') {
        /* use resolver output */
    } else {
        copy_string(target->tclass, sizeof(target->tclass), mode_to_tclass(raw->mode));
    }

    if (ops->sid_to_context(raw->sid, target->tcontext, sizeof(target->tcontext)) != 0) {
        return -EINVAL;
    }

    return 0;
}

static void fill_result(const struct lha_kernel_ops *ops,
                        const struct lha_capture_event_v1 *event,
                        struct lha_result_v1 *result)
{
    memset(result, 0, sizeof(*result));
    result->ret = event->ret;
    classify_runtime_result(event->ret, result->runtime_result, sizeof(result->runtime_result));
    resolve_policy_result(ops, event, result);
}

static int resolve_inode_permission(const struct lha_kernel_ops *ops,
                                    const struct lha_capture_event_v1 *event,
                                    struct lha_enriched_event_v1 *out)
{
    struct lha_inode_raw inode;

    if (ops == NULL || ops->resolve_inode == NULL) {
        return -EINVAL;
    }

    memset(&inode, 0, sizeof(inode));
    if (ops->resolve_inode(event->args.inode_permission.inode, event->ts_ns, &inode) != 0) {
        return -EINVAL;
    }

    copy_string(out->hook, sizeof(out->hook), "selinux_inode_permission");
    copy_string(out->hook_signature, sizeof(out->hook_signature),
                "static int selinux_inode_permission(struct inode *inode, int mask)");

    if (fill_subject(ops, event, event->ts_ns, &out->subject) != 0) {
        return -EINVAL;
    }
    if (fill_target_from_inode_raw(ops, &inode, &out->target) != 0) {
        return -EINVAL;
    }

    out->request.mask_raw = event->args.inode_permission.mask;
    copy_string(out->request.obj_type, sizeof(out->request.obj_type), mode_to_obj_type(inode.mode));
    decode_mask_perm(inode.mode, event->args.inode_permission.mask,
                     (event->args.inode_permission.mask & LHA_MAY_OPEN) != 0,
                     out->request.perm, sizeof(out->request.perm));
    fill_result(ops, event, &out->result);
    return 0;
}

static int resolve_file_open(const struct lha_kernel_ops *ops,
                             const struct lha_capture_event_v1 *event,
                             struct lha_enriched_event_v1 *out)
{
    struct lha_file_raw file;

    if (ops == NULL || ops->resolve_file == NULL) {
        return -EINVAL;
    }

    memset(&file, 0, sizeof(file));
    if (ops->resolve_file(event->args.file_open.file, event->ts_ns, &file) != 0) {
        return -EINVAL;
    }

    copy_string(out->hook, sizeof(out->hook), "selinux_file_open");
    copy_string(out->hook_signature, sizeof(out->hook_signature),
                "static int selinux_file_open(struct file *file)");

    if (fill_subject(ops, event, event->ts_ns, &out->subject) != 0) {
        return -EINVAL;
    }
    if (fill_target_from_inode_raw(ops, &file.inode, &out->target) != 0) {
        return -EINVAL;
    }

    out->request.mask_raw = 0;
    copy_string(out->request.obj_type, sizeof(out->request.obj_type),
                mode_to_obj_type(file.inode.mode));
    decode_file_open_perm(&file, out->request.perm, sizeof(out->request.perm));
    fill_result(ops, event, &out->result);
    return 0;
}

static int resolve_file_permission(const struct lha_kernel_ops *ops,
                                   const struct lha_capture_event_v1 *event,
                                   struct lha_enriched_event_v1 *out)
{
    struct lha_file_raw file;
    int effective_mask;

    if (ops == NULL || ops->resolve_file == NULL) {
        return -EINVAL;
    }

    memset(&file, 0, sizeof(file));
    if (ops->resolve_file(event->args.file_permission.file, event->ts_ns, &file) != 0) {
        return -EINVAL;
    }

    effective_mask = event->args.file_permission.mask;
    if ((file.f_flags & O_APPEND) != 0 && (effective_mask & LHA_MAY_WRITE) != 0) {
        effective_mask |= LHA_MAY_APPEND;
    }

    copy_string(out->hook, sizeof(out->hook), "selinux_file_permission");
    copy_string(out->hook_signature, sizeof(out->hook_signature),
                "static int selinux_file_permission(struct file *file, int mask)");

    if (fill_subject(ops, event, event->ts_ns, &out->subject) != 0) {
        return -EINVAL;
    }
    if (fill_target_from_inode_raw(ops, &file.inode, &out->target) != 0) {
        return -EINVAL;
    }

    out->request.mask_raw = event->args.file_permission.mask;
    copy_string(out->request.obj_type, sizeof(out->request.obj_type),
                mode_to_obj_type(file.inode.mode));
    decode_mask_perm(file.inode.mode, effective_mask, false,
                     out->request.perm, sizeof(out->request.perm));
    fill_result(ops, event, &out->result);
    return 0;
}

int lha_resolve_event(const struct lha_kernel_ops *ops,
                      const struct lha_capture_event_v1 *event,
                      struct lha_enriched_event_v1 *out)
{
    if (ops == NULL || event == NULL || out == NULL || event->version != 1u) {
        return -EINVAL;
    }

    memset(out, 0, sizeof(*out));
    out->version = event->version;
    out->hook_id = event->hook_id;
    out->timestamp_ns = event->ts_ns;

    switch (event->hook_id) {
    case LHA_HOOK_INODE_PERMISSION:
        return resolve_inode_permission(ops, event, out);
    case LHA_HOOK_FILE_OPEN:
        return resolve_file_open(ops, event, out);
    case LHA_HOOK_FILE_PERMISSION:
        return resolve_file_permission(ops, event, out);
    default:
        return -EINVAL;
    }
}
