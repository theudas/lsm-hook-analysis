// SPDX-License-Identifier: MIT
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/xattr.h>
#endif

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define LHA_MAY_EXEC   0x00000001
#define LHA_MAY_WRITE  0x00000002
#define LHA_MAY_READ   0x00000004
#define LHA_MAY_APPEND 0x00000008
#define LHA_MAY_OPEN   0x00000020

#define MOCK_FMODE_READ  0x1
#define MOCK_FMODE_WRITE 0x2
#define MOCK_FMODE_EXEC  0x4

#define MAX_CTX_LEN 128
#define MAX_COMM_LEN 64
#define MAX_PERM_LEN 64
#define MAX_TYPE_LEN 16
#define MAX_DEV_LEN 32
#define MAX_HOOK_LEN 64
#define MAX_SIG_LEN 96

enum hook_kind {
    HOOK_INODE_PERMISSION = 0,
    HOOK_FILE_OPEN,
    HOOK_FILE_PERMISSION,
};

enum policy_hint {
    POLICY_HINT_UNKNOWN = 0,
    POLICY_HINT_ALLOW,
    POLICY_HINT_DENY,
};

struct mock_super_block {
    char s_id[MAX_DEV_LEN];
};

struct mock_inode_security {
    uint32_t sid;
    char sclass[MAX_TYPE_LEN];
    char context[MAX_CTX_LEN];
};

struct mock_inode {
    mode_t i_mode;
    uint64_t i_ino;
    struct mock_super_block i_sb;
    struct mock_inode_security isec;
    char path[PATH_MAX];
};

struct mock_file {
    int fd;
    int f_flags;
    unsigned int f_mode;
    struct mock_inode *inode;
    char path[PATH_MAX];
};

struct mock_cred {
    uint32_t sid;
    char scontext[MAX_CTX_LEN];
};

struct mock_task_struct {
    pid_t pid;
    uint64_t tid;
    char comm[MAX_COMM_LEN];
    struct mock_cred cred;
};

struct parsed_subject {
    pid_t pid;
    uint64_t tid;
    char scontext[MAX_CTX_LEN];
    char comm[MAX_COMM_LEN];
};

struct parsed_request {
    int mask_raw;
    char obj_type[MAX_TYPE_LEN];
    char perm[MAX_PERM_LEN];
};

struct parsed_target {
    char dev[MAX_DEV_LEN];
    uint64_t ino;
    char type[MAX_TYPE_LEN];
    char path[PATH_MAX];
    char tclass[MAX_TYPE_LEN];
    char tcontext[MAX_CTX_LEN];
};

struct parsed_result {
    int ret;
    char runtime_result[16];
    char policy_result[16];
};

struct parsed_event {
    char hook[MAX_HOOK_LEN];
    char hook_signature[MAX_SIG_LEN];
    uint64_t timestamp_ns;
    struct parsed_subject subject;
    struct parsed_request request;
    struct parsed_target target;
    struct parsed_result result;
};

struct hook_invocation {
    enum hook_kind kind;
    int ret;
    enum policy_hint policy;
    union {
        struct {
            const struct mock_inode *inode;
            int mask;
        } inode_permission;
        struct {
            const struct mock_file *file;
        } file_open;
        struct {
            const struct mock_file *file;
            int mask;
        } file_permission;
    } args;
};

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

static uint32_t fnv1a32(const char *text)
{
    uint32_t hash = 2166136261u;
    size_t i;

    if (text == NULL) {
        return 0;
    }

    for (i = 0; text[i] != '\0'; ++i) {
        hash ^= (unsigned char)text[i];
        hash *= 16777619u;
    }
    return hash;
}

static uint64_t now_ns(void)
{
    struct timespec ts;

#if defined(CLOCK_REALTIME)
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
#else
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
        return 0;
    }
#endif

    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static uint64_t current_tid(void)
{
#if defined(__linux__)
    return (uint64_t)syscall(SYS_gettid);
#elif defined(__APPLE__)
    uint64_t tid = 0;

    if (pthread_threadid_np(NULL, &tid) != 0) {
        return (uint64_t)getpid();
    }
    return tid;
#else
    return (uint64_t)getpid();
#endif
}

static bool read_first_line(const char *path, char *buf, size_t buf_len)
{
    FILE *fp;

    if (buf_len == 0) {
        return false;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        buf[0] = '\0';
        return false;
    }

    if (fgets(buf, (int)buf_len, fp) == NULL) {
        fclose(fp);
        buf[0] = '\0';
        return false;
    }

    fclose(fp);
    buf[strcspn(buf, "\r\n")] = '\0';
    return true;
}

static void basename_from_path(const char *path, char *buf, size_t buf_len)
{
    const char *slash;

    if (path == NULL || path[0] == '\0') {
        copy_string(buf, buf_len, "unknown");
        return;
    }

    slash = strrchr(path, '/');
    if (slash != NULL && slash[1] != '\0') {
        copy_string(buf, buf_len, slash + 1);
        return;
    }

    copy_string(buf, buf_len, path);
}

static const char *mode_to_obj_type(mode_t mode)
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

static const char *mode_to_tclass(mode_t mode)
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
    if (buf[0] != '\0') {
        strncat(buf, "|", buf_len - strlen(buf) - 1);
    }
    strncat(buf, perm, buf_len - strlen(buf) - 1);
}

static void decode_mask_perm(mode_t mode, int mask, bool add_open, char *buf, size_t buf_len)
{
    int eff = mask & (LHA_MAY_READ | LHA_MAY_WRITE | LHA_MAY_EXEC | LHA_MAY_APPEND);

    buf[0] = '\0';
    if (add_open) {
        append_perm(buf, buf_len, "open");
    }

    if (eff == 0) {
        if (buf[0] == '\0') {
            append_perm(buf, buf_len, "none");
        }
        return;
    }

    if (S_ISDIR(mode)) {
        if (eff & LHA_MAY_READ) {
            append_perm(buf, buf_len, "read");
        }
        if (eff & LHA_MAY_WRITE) {
            append_perm(buf, buf_len, "write");
        }
        if (eff & LHA_MAY_EXEC) {
            append_perm(buf, buf_len, "search");
        }
        return;
    }

    if (eff & LHA_MAY_READ) {
        append_perm(buf, buf_len, "read");
    }
    if (eff & LHA_MAY_EXEC) {
        append_perm(buf, buf_len, "exec");
    }
    if (eff & LHA_MAY_APPEND) {
        append_perm(buf, buf_len, "append");
    } else if (eff & LHA_MAY_WRITE) {
        append_perm(buf, buf_len, "write");
    }
}

static void decode_file_open_perm(const struct mock_file *file, char *buf, size_t buf_len)
{
    buf[0] = '\0';
    append_perm(buf, buf_len, "open");

    if (file->f_mode & MOCK_FMODE_READ) {
        append_perm(buf, buf_len, "read");
    }
    if (file->f_mode & MOCK_FMODE_WRITE) {
        if (file->f_flags & O_APPEND) {
            append_perm(buf, buf_len, "append");
        } else {
            append_perm(buf, buf_len, "write");
        }
    }
    if (file->f_mode & MOCK_FMODE_EXEC) {
        append_perm(buf, buf_len, S_ISDIR(file->inode->i_mode) ? "search" : "exec");
    }
}

static void classify_runtime_result(int ret, char *buf, size_t buf_len)
{
    if (ret == 0) {
        copy_string(buf, buf_len, "allow");
        return;
    }
    if (ret == -EACCES || ret == -EPERM) {
        copy_string(buf, buf_len, "deny");
        return;
    }
    copy_string(buf, buf_len, "error");
}

static void classify_policy_result(int ret, enum policy_hint hint, char *buf, size_t buf_len)
{
    if (hint == POLICY_HINT_ALLOW) {
        copy_string(buf, buf_len, "allow");
        return;
    }
    if (hint == POLICY_HINT_DENY) {
        copy_string(buf, buf_len, "deny");
        return;
    }
    if (ret == -EACCES || ret == -EPERM) {
        copy_string(buf, buf_len, "deny");
        return;
    }
    copy_string(buf, buf_len, "unknown");
}

static void build_fallback_subject_context(char *buf, size_t buf_len, const char *comm)
{
    char type_name[64];
    size_t i;

    copy_string(type_name, sizeof(type_name), comm != NULL ? comm : "demo");
    for (i = 0; type_name[i] != '\0'; ++i) {
        if (type_name[i] == ' ') {
            type_name[i] = '_';
        }
    }
    snprintf(buf, buf_len, "mock_u:mock_r:%s_t:s0", type_name);
}

static bool read_selinux_xattr(const char *path, char *buf, size_t buf_len)
{
#if defined(__linux__)
    ssize_t n = getxattr(path, "security.selinux", buf, buf_len - 1);

    if (n <= 0) {
        return false;
    }
    buf[n] = '\0';
    return true;
#elif defined(__APPLE__)
    ssize_t n = getxattr(path, "security.selinux", buf, buf_len - 1, 0, 0);

    if (n <= 0) {
        return false;
    }
    buf[n] = '\0';
    return true;
#else
    (void)path;
    (void)buf;
    (void)buf_len;
    return false;
#endif
}

static void build_fallback_target_context(const struct mock_inode *inode, char *buf, size_t buf_len)
{
    if (S_ISDIR(inode->i_mode)) {
        copy_string(buf, buf_len, "mock_u:object_r:dir_t:s0");
    } else if (S_ISREG(inode->i_mode) && (inode->i_mode & 0111) != 0) {
        copy_string(buf, buf_len, "mock_u:object_r:bin_t:s0");
    } else if (S_ISREG(inode->i_mode)) {
        copy_string(buf, buf_len, "mock_u:object_r:file_t:s0");
    } else {
        copy_string(buf, buf_len, "mock_u:object_r:object_t:s0");
    }
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0755) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int write_text_file(const char *path, const char *content, mode_t mode)
{
    FILE *fp = fopen(path, "w");

    if (fp == NULL) {
        return -1;
    }
    if (fputs(content, fp) == EOF) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (chmod(path, mode) != 0) {
        return -1;
    }
    return 0;
}

static int prepare_fixtures(char *dir_path, size_t dir_len, char *file_path, size_t file_len,
                            char *append_path, size_t append_len)
{
    char cwd[PATH_MAX];
    char fixture_root[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        return -1;
    }

    snprintf(fixture_root, sizeof(fixture_root), "%s/mock-fixtures", cwd);
    snprintf(dir_path, dir_len, "%s/data", fixture_root);
    snprintf(file_path, file_len, "%s/sample.txt", dir_path);
    snprintf(append_path, append_len, "%s/append.log", dir_path);

    if (ensure_dir(fixture_root) != 0 || ensure_dir(dir_path) != 0) {
        return -1;
    }
    if (write_text_file(file_path, "hello from mock file\n", 0644) != 0) {
        return -1;
    }
    if (write_text_file(append_path, "seed line\n", 0644) != 0) {
        return -1;
    }
    return 0;
}

static int init_current_task(struct mock_task_struct *task, const char *argv0)
{
    char comm[MAX_COMM_LEN];
    char ctx[MAX_CTX_LEN];

    memset(task, 0, sizeof(*task));
    task->pid = getpid();
    task->tid = current_tid();

    if (!read_first_line("/proc/self/comm", comm, sizeof(comm))) {
        basename_from_path(argv0, comm, sizeof(comm));
    }
    copy_string(task->comm, sizeof(task->comm), comm);

    if (!read_first_line("/proc/self/attr/current", ctx, sizeof(ctx))) {
        build_fallback_subject_context(ctx, sizeof(ctx), task->comm);
    }
    copy_string(task->cred.scontext, sizeof(task->cred.scontext), ctx);
    task->cred.sid = fnv1a32(task->cred.scontext);
    return 0;
}

static int build_mock_inode(const char *path, struct mock_inode *inode)
{
    struct stat st;
    char abs_path[PATH_MAX];
    char ctx[MAX_CTX_LEN];

    memset(inode, 0, sizeof(*inode));
    if (realpath(path, abs_path) == NULL) {
        return -1;
    }
    if (lstat(abs_path, &st) != 0) {
        return -1;
    }

    inode->i_mode = st.st_mode;
    inode->i_ino = (uint64_t)st.st_ino;
    copy_string(inode->path, sizeof(inode->path), abs_path);
    snprintf(inode->i_sb.s_id, sizeof(inode->i_sb.s_id), "dev-%llu",
             (unsigned long long)st.st_dev);
    copy_string(inode->isec.sclass, sizeof(inode->isec.sclass), mode_to_tclass(st.st_mode));

    if (!read_selinux_xattr(abs_path, ctx, sizeof(ctx))) {
        build_fallback_target_context(inode, ctx, sizeof(ctx));
    }
    copy_string(inode->isec.context, sizeof(inode->isec.context), ctx);
    inode->isec.sid = fnv1a32(inode->isec.context);
    return 0;
}

static int build_mock_file(const char *path, int open_flags, struct mock_inode *inode, struct mock_file *file)
{
    int accmode;

    memset(file, 0, sizeof(*file));
    file->fd = open(path, open_flags, 0644);
    if (file->fd < 0) {
        return -1;
    }

    file->inode = inode;
    file->f_flags = open_flags;
    copy_string(file->path, sizeof(file->path), inode->path);

    accmode = open_flags & O_ACCMODE;
    if (accmode == O_RDONLY || accmode == O_RDWR) {
        file->f_mode |= MOCK_FMODE_READ;
    }
    if (accmode == O_WRONLY || accmode == O_RDWR) {
        file->f_mode |= MOCK_FMODE_WRITE;
    }
#ifdef O_EXEC
    if ((open_flags & O_EXEC) != 0) {
        file->f_mode |= MOCK_FMODE_EXEC;
    }
#endif
    return 0;
}

static void close_mock_file(struct mock_file *file)
{
    if (file->fd >= 0) {
        close(file->fd);
        file->fd = -1;
    }
}

static void fill_subject(const struct mock_task_struct *task, struct parsed_subject *subject)
{
    memset(subject, 0, sizeof(*subject));
    subject->pid = task->pid;
    subject->tid = task->tid;
    copy_string(subject->comm, sizeof(subject->comm), task->comm);
    copy_string(subject->scontext, sizeof(subject->scontext), task->cred.scontext);
}

static void fill_target_from_inode(const struct mock_inode *inode, struct parsed_target *target)
{
    memset(target, 0, sizeof(*target));
    copy_string(target->dev, sizeof(target->dev), inode->i_sb.s_id);
    target->ino = inode->i_ino;
    copy_string(target->type, sizeof(target->type), mode_to_obj_type(inode->i_mode));
    copy_string(target->path, sizeof(target->path), inode->path);
    copy_string(target->tclass, sizeof(target->tclass), inode->isec.sclass);
    copy_string(target->tcontext, sizeof(target->tcontext), inode->isec.context);
}

static void fill_result(int ret, enum policy_hint hint, struct parsed_result *result)
{
    memset(result, 0, sizeof(*result));
    result->ret = ret;
    classify_runtime_result(ret, result->runtime_result, sizeof(result->runtime_result));
    classify_policy_result(ret, hint, result->policy_result, sizeof(result->policy_result));
}

static void parse_inode_permission(const struct mock_task_struct *task,
                                   const struct hook_invocation *invocation,
                                   struct parsed_event *event)
{
    const struct mock_inode *inode = invocation->args.inode_permission.inode;

    memset(event, 0, sizeof(*event));
    copy_string(event->hook, sizeof(event->hook), "selinux_inode_permission");
    copy_string(event->hook_signature, sizeof(event->hook_signature),
                "static int selinux_inode_permission(struct inode *inode, int mask)");
    event->timestamp_ns = now_ns();
    fill_subject(task, &event->subject);
    fill_target_from_inode(inode, &event->target);
    event->request.mask_raw = invocation->args.inode_permission.mask;
    copy_string(event->request.obj_type, sizeof(event->request.obj_type), mode_to_obj_type(inode->i_mode));
    decode_mask_perm(inode->i_mode, invocation->args.inode_permission.mask,
                     (invocation->args.inode_permission.mask & LHA_MAY_OPEN) != 0,
                     event->request.perm, sizeof(event->request.perm));
    fill_result(invocation->ret, invocation->policy, &event->result);
}

static void parse_file_open(const struct mock_task_struct *task,
                            const struct hook_invocation *invocation,
                            struct parsed_event *event)
{
    const struct mock_file *file = invocation->args.file_open.file;

    memset(event, 0, sizeof(*event));
    copy_string(event->hook, sizeof(event->hook), "selinux_file_open");
    copy_string(event->hook_signature, sizeof(event->hook_signature),
                "static int selinux_file_open(struct file *file)");
    event->timestamp_ns = now_ns();
    fill_subject(task, &event->subject);
    fill_target_from_inode(file->inode, &event->target);
    event->request.mask_raw = 0;
    copy_string(event->request.obj_type, sizeof(event->request.obj_type), mode_to_obj_type(file->inode->i_mode));
    decode_file_open_perm(file, event->request.perm, sizeof(event->request.perm));
    fill_result(invocation->ret, invocation->policy, &event->result);
}

static void parse_file_permission(const struct mock_task_struct *task,
                                  const struct hook_invocation *invocation,
                                  struct parsed_event *event)
{
    const struct mock_file *file = invocation->args.file_permission.file;
    int raw_mask = invocation->args.file_permission.mask;
    int effective_mask = raw_mask;

    if ((file->f_flags & O_APPEND) != 0 && (effective_mask & LHA_MAY_WRITE) != 0) {
        effective_mask |= LHA_MAY_APPEND;
    }

    memset(event, 0, sizeof(*event));
    copy_string(event->hook, sizeof(event->hook), "selinux_file_permission");
    copy_string(event->hook_signature, sizeof(event->hook_signature),
                "static int selinux_file_permission(struct file *file, int mask)");
    event->timestamp_ns = now_ns();
    fill_subject(task, &event->subject);
    fill_target_from_inode(file->inode, &event->target);
    event->request.mask_raw = raw_mask;
    copy_string(event->request.obj_type, sizeof(event->request.obj_type), mode_to_obj_type(file->inode->i_mode));
    decode_mask_perm(file->inode->i_mode, effective_mask, false, event->request.perm, sizeof(event->request.perm));
    fill_result(invocation->ret, invocation->policy, &event->result);
}

static void parse_invocation(const struct mock_task_struct *task,
                             const struct hook_invocation *invocation,
                             struct parsed_event *event)
{
    switch (invocation->kind) {
    case HOOK_INODE_PERMISSION:
        parse_inode_permission(task, invocation, event);
        break;
    case HOOK_FILE_OPEN:
        parse_file_open(task, invocation, event);
        break;
    case HOOK_FILE_PERMISSION:
        parse_file_permission(task, invocation, event);
        break;
    }
}

static void print_json_string(FILE *out, const char *text)
{
    const unsigned char *p = (const unsigned char *)(text != NULL ? text : "");

    fputc('"', out);
    while (*p != '\0') {
        switch (*p) {
        case '\\':
            fputs("\\\\", out);
            break;
        case '"':
            fputs("\\\"", out);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        case '\f':
            fputs("\\f", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20) {
                fprintf(out, "\\u%04x", *p);
            } else {
                fputc(*p, out);
            }
            break;
        }
        ++p;
    }
    fputc('"', out);
}

static void print_event_json(FILE *out, const struct parsed_event *event, bool last)
{
    fprintf(out, "    {\n");
    fprintf(out, "      \"hook\": ");
    print_json_string(out, event->hook);
    fprintf(out, ",\n");
    fprintf(out, "      \"hook_signature\": ");
    print_json_string(out, event->hook_signature);
    fprintf(out, ",\n");
    fprintf(out, "      \"timestamp_ns\": %llu,\n", (unsigned long long)event->timestamp_ns);

    fprintf(out, "      \"subject\": {\n");
    fprintf(out, "        \"pid\": %d,\n", event->subject.pid);
    fprintf(out, "        \"tid\": %llu,\n", (unsigned long long)event->subject.tid);
    fprintf(out, "        \"scontext\": ");
    print_json_string(out, event->subject.scontext);
    fprintf(out, ",\n");
    fprintf(out, "        \"comm\": ");
    print_json_string(out, event->subject.comm);
    fprintf(out, "\n");
    fprintf(out, "      },\n");

    fprintf(out, "      \"request\": {\n");
    fprintf(out, "        \"mask_raw\": %d,\n", event->request.mask_raw);
    fprintf(out, "        \"obj_type\": ");
    print_json_string(out, event->request.obj_type);
    fprintf(out, ",\n");
    fprintf(out, "        \"perm\": ");
    print_json_string(out, event->request.perm);
    fprintf(out, "\n");
    fprintf(out, "      },\n");

    fprintf(out, "      \"target\": {\n");
    fprintf(out, "        \"dev\": ");
    print_json_string(out, event->target.dev);
    fprintf(out, ",\n");
    fprintf(out, "        \"ino\": %llu,\n", (unsigned long long)event->target.ino);
    fprintf(out, "        \"type\": ");
    print_json_string(out, event->target.type);
    fprintf(out, ",\n");
    fprintf(out, "        \"path\": ");
    print_json_string(out, event->target.path);
    fprintf(out, ",\n");
    fprintf(out, "        \"tclass\": ");
    print_json_string(out, event->target.tclass);
    fprintf(out, ",\n");
    fprintf(out, "        \"tcontext\": ");
    print_json_string(out, event->target.tcontext);
    fprintf(out, "\n");
    fprintf(out, "      },\n");

    fprintf(out, "      \"result\": {\n");
    fprintf(out, "        \"ret\": %d,\n", event->result.ret);
    fprintf(out, "        \"runtime_result\": ");
    print_json_string(out, event->result.runtime_result);
    fprintf(out, ",\n");
    fprintf(out, "        \"policy_result\": ");
    print_json_string(out, event->result.policy_result);
    fprintf(out, "\n");
    fprintf(out, "      }\n");
    fprintf(out, "    }%s\n", last ? "" : ",");
}

int main(int argc, char **argv)
{
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    char append_path[PATH_MAX];
    struct mock_task_struct current_task;
    struct mock_inode dir_inode;
    struct mock_inode file_inode;
    struct mock_inode append_inode;
    struct mock_file read_file = { .fd = -1 };
    struct mock_file append_file = { .fd = -1 };
    struct hook_invocation invocations[3];
    struct parsed_event events[3];
    char read_buf[32];
    size_t i;

    (void)argc;

    if (prepare_fixtures(dir_path, sizeof(dir_path), file_path, sizeof(file_path),
                         append_path, sizeof(append_path)) != 0) {
        perror("prepare_fixtures");
        return 1;
    }
    if (init_current_task(&current_task, argv[0]) != 0) {
        fprintf(stderr, "failed to initialize mock current task\n");
        return 1;
    }
    if (build_mock_inode(dir_path, &dir_inode) != 0 ||
        build_mock_inode(file_path, &file_inode) != 0 ||
        build_mock_inode(append_path, &append_inode) != 0) {
        perror("build_mock_inode");
        return 1;
    }
    if (build_mock_file(file_path, O_RDONLY, &file_inode, &read_file) != 0) {
        perror("build_mock_file(read)");
        return 1;
    }
    if (build_mock_file(append_path, O_WRONLY | O_APPEND, &append_inode, &append_file) != 0) {
        perror("build_mock_file(append)");
        close_mock_file(&read_file);
        return 1;
    }

    (void)read(read_file.fd, read_buf, sizeof(read_buf));

    invocations[0].kind = HOOK_INODE_PERMISSION;
    invocations[0].ret = 0;
    invocations[0].policy = POLICY_HINT_ALLOW;
    invocations[0].args.inode_permission.inode = &dir_inode;
    invocations[0].args.inode_permission.mask = LHA_MAY_EXEC;

    invocations[1].kind = HOOK_FILE_OPEN;
    invocations[1].ret = 0;
    invocations[1].policy = POLICY_HINT_ALLOW;
    invocations[1].args.file_open.file = &read_file;

    invocations[2].kind = HOOK_FILE_PERMISSION;
    invocations[2].ret = -EACCES;
    invocations[2].policy = POLICY_HINT_DENY;
    invocations[2].args.file_permission.file = &append_file;
    invocations[2].args.file_permission.mask = LHA_MAY_WRITE;

    for (i = 0; i < 3; ++i) {
        parse_invocation(&current_task, &invocations[i], &events[i]);
    }

    printf("{\n");
    printf("  \"generated_at_ns\": %llu,\n", (unsigned long long)now_ns());
    printf("  \"fixtures\": {\n");
    printf("    \"directory\": ");
    print_json_string(stdout, dir_inode.path);
    printf(",\n");
    printf("    \"read_file\": ");
    print_json_string(stdout, file_inode.path);
    printf(",\n");
    printf("    \"append_file\": ");
    print_json_string(stdout, append_inode.path);
    printf("\n");
    printf("  },\n");
    printf("  \"events\": [\n");
    for (i = 0; i < 3; ++i) {
        print_event_json(stdout, &events[i], i == 2);
    }
    printf("  ]\n");
    printf("}\n");

    close_mock_file(&read_file);
    close_mock_file(&append_file);
    return 0;
}
