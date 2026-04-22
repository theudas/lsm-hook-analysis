#include "lha_json.h"
#include "lha_resolver.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int mock_resolve_current_subject(uint64_t ts_ns, struct lha_subject_raw *subject)
{
    (void)ts_ns;
    memset(subject, 0, sizeof(*subject));
    subject->pid = 4321;
    subject->tid = 4322;
    subject->sid = 100;
    snprintf(subject->comm, sizeof(subject->comm), "%s", "demo-task");
    return 0;
}

static int mock_resolve_inode(const void *inode, uint64_t ts_ns, struct lha_inode_raw *target)
{
    (void)inode;
    (void)ts_ns;
    memset(target, 0, sizeof(*target));
    target->mode = S_IFDIR | 0755;
    target->ino = 101;
    target->sid = 200;
    target->sclass = 2;
    snprintf(target->dev, sizeof(target->dev), "%s", "dm-0");
    snprintf(target->path, sizeof(target->path), "%s", "/tmp/data");
    return 0;
}

static int mock_resolve_file(const void *file, uint64_t ts_ns, struct lha_file_raw *target)
{
    uintptr_t id = (uintptr_t)file;

    (void)ts_ns;
    memset(target, 0, sizeof(*target));
    target->inode.mode = S_IFREG | 0644;
    target->inode.sid = 201;
    target->inode.sclass = 1;
    target->inode.ino = (uint64_t)(1000 + id);
    snprintf(target->inode.dev, sizeof(target->inode.dev), "%s", "dm-3");

    if (id == 1u) {
        target->f_mode = LHA_FILE_MODE_READ;
        snprintf(target->inode.path, sizeof(target->inode.path), "%s",
                 "/data/local/tmp/read.txt");
        return 0;
    }

    target->f_mode = LHA_FILE_MODE_WRITE;
    target->f_flags = O_APPEND;
    snprintf(target->inode.path, sizeof(target->inode.path), "%s",
             "/data/local/tmp/append.log");
    return 0;
}

static int mock_sid_to_context(uint32_t sid, char *buf, size_t buf_len)
{
    const char *context = "";

    switch (sid) {
    case 100:
        context = "u:r:subject_t:s0";
        break;
    case 200:
        context = "u:object_r:dir_t:s0";
        break;
    case 201:
        context = "u:object_r:file_t:s0";
        break;
    default:
        return -1;
    }

    snprintf(buf, buf_len, "%s", context);
    return 0;
}

static int mock_sclass_to_string(uint16_t sclass, char *buf, size_t buf_len)
{
    const char *name = "";

    switch (sclass) {
    case 1:
        name = "file";
        break;
    case 2:
        name = "dir";
        break;
    default:
        return -1;
    }

    snprintf(buf, buf_len, "%s", name);
    return 0;
}

static int mock_policy_result(const struct lha_capture_event_v1 *event, char *buf, size_t buf_len)
{
    const char *value = "unknown";

    if (event->hook_id == LHA_HOOK_INODE_PERMISSION) {
        value = "allow";
    } else if (event->hook_id == LHA_HOOK_FILE_PERMISSION) {
        value = "deny";
    }

    snprintf(buf, buf_len, "%s", value);
    return 0;
}

static void test_inode_permission(const struct lha_kernel_ops *ops)
{
    struct lha_capture_event_v1 input;
    struct lha_enriched_event_v1 output;

    memset(&input, 0, sizeof(input));
    input.version = 1;
    input.hook_id = LHA_HOOK_INODE_PERMISSION;
    input.ts_ns = 111;
    input.ret = 0;
    input.args.inode_permission.inode = (const void *)1;
    input.args.inode_permission.mask = LHA_MAY_EXEC;

    assert(lha_resolve_event(ops, &input, &output) == 0);
    assert(strcmp(output.hook, "selinux_inode_permission") == 0);
    assert(output.subject.pid == 4321u);
    assert(strcmp(output.subject.scontext, "u:r:subject_t:s0") == 0);
    assert(strcmp(output.request.obj_type, "dir") == 0);
    assert(strcmp(output.request.perm, "search") == 0);
    assert(strcmp(output.target.tclass, "dir") == 0);
    assert(strcmp(output.result.runtime_result, "allow") == 0);
    assert(strcmp(output.result.policy_result, "allow") == 0);
}

static void test_file_open(const struct lha_kernel_ops *ops)
{
    struct lha_capture_event_v1 input;
    struct lha_enriched_event_v1 output;
    char json[2048];

    memset(&input, 0, sizeof(input));
    input.version = 1;
    input.hook_id = LHA_HOOK_FILE_OPEN;
    input.ts_ns = 222;
    input.ret = 0;
    input.args.file_open.file = (const void *)1;

    assert(lha_resolve_event(ops, &input, &output) == 0);
    assert(strcmp(output.request.perm, "open|read") == 0);
    assert(strcmp(output.target.path, "/data/local/tmp/read.txt") == 0);
    assert(lha_event_to_json(&output, json, sizeof(json)) > 0);
    assert(strstr(json, "\"hook\": \"selinux_file_open\"") != NULL);
    assert(strstr(json, "\"perm\": \"open|read\"") != NULL);
}

static void test_file_permission(const struct lha_kernel_ops *ops)
{
    struct lha_capture_event_v1 input;
    struct lha_enriched_event_v1 output;

    memset(&input, 0, sizeof(input));
    input.version = 1;
    input.hook_id = LHA_HOOK_FILE_PERMISSION;
    input.ts_ns = 333;
    input.ret = -13;
    input.args.file_permission.file = (const void *)2;
    input.args.file_permission.mask = LHA_MAY_WRITE;

    assert(lha_resolve_event(ops, &input, &output) == 0);
    assert(strcmp(output.request.perm, "append") == 0);
    assert(strcmp(output.result.runtime_result, "deny") == 0);
    assert(strcmp(output.result.policy_result, "deny") == 0);
}

int main(void)
{
    struct lha_kernel_ops ops;

    memset(&ops, 0, sizeof(ops));
    ops.resolve_current_subject = mock_resolve_current_subject;
    ops.resolve_inode = mock_resolve_inode;
    ops.resolve_file = mock_resolve_file;
    ops.sid_to_context = mock_sid_to_context;
    ops.sclass_to_string = mock_sclass_to_string;
    ops.resolve_policy_result = mock_policy_result;

    test_inode_permission(&ops);
    test_file_open(&ops);
    test_file_permission(&ops);

    puts("ok");
    return 0;
}
