#include "lha_avc.h"
#include "lha_json.h"
#include "lha_resolver.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int mock_resolve_subject(const void *task, const void *cred, uint64_t ts_ns,
                                struct lha_subject_raw *subject)
{
    uintptr_t task_id = (uintptr_t)task;
    uintptr_t cred_id = (uintptr_t)cred;

    (void)ts_ns;
    memset(subject, 0, sizeof(*subject));
    subject->pid = 4300u + (uint32_t)task_id;
    subject->tid = 5300u + (uint32_t)task_id;
    subject->sid = 100u + (uint32_t)cred_id;
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
    case 101:
        context = "u:r:subject_alt_t:s0";
        break;
    case 102:
        context = "u:r:subject_async_t:s0";
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

static void prepare_file_open_event(const struct lha_kernel_ops *ops,
                                    struct lha_enriched_event_v1 *output)
{
    struct lha_capture_event_v1 input;

    memset(&input, 0, sizeof(input));
    input.version = 1;
    input.hook_id = LHA_HOOK_FILE_OPEN;
    input.ts_ns = 222;
    input.ret = 0;
    input.subject.task = (const void *)2;
    input.subject.cred = (const void *)2;
    input.args.file_open.file = (const void *)1;

    assert(lha_resolve_event(ops, &input, output) == 0);
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
    input.subject.task = (const void *)1;
    input.subject.cred = (const void *)1;
    input.args.inode_permission.inode = (const void *)1;
    input.args.inode_permission.mask = LHA_MAY_EXEC;

    assert(lha_resolve_event(ops, &input, &output) == 0);
    assert(strcmp(output.hook, "selinux_inode_permission") == 0);
    assert(output.subject.pid == 4301u);
    assert(strcmp(output.subject.scontext, "u:r:subject_alt_t:s0") == 0);
    assert(strcmp(output.request.obj_type, "dir") == 0);
    assert(strcmp(output.request.perm, "search") == 0);
    assert(strcmp(output.target.tclass, "dir") == 0);
    assert(strcmp(output.result.runtime_result, "allow") == 0);
    assert(strcmp(output.result.policy_result, "allow") == 0);
}

static void test_policy_state_override(const struct lha_kernel_ops *ops)
{
    struct lha_capture_event_v1 input;
    struct lha_enriched_event_v1 output;

    memset(&input, 0, sizeof(input));
    input.version = 1;
    input.hook_id = LHA_HOOK_FILE_OPEN;
    input.ts_ns = 211;
    input.ret = 0;
    input.policy_state = LHA_POLICY_DENY;
    input.subject.task = (const void *)2;
    input.subject.cred = (const void *)2;
    input.args.file_open.file = (const void *)1;

    assert(lha_resolve_event(ops, &input, &output) == 0);
    assert(strcmp(output.result.runtime_result, "allow") == 0);
    assert(strcmp(output.result.policy_result, "deny") == 0);
}

static void test_policy_state_inferred_allow(const struct lha_kernel_ops *ops)
{
    struct lha_capture_event_v1 input;
    struct lha_enriched_event_v1 output;

    memset(&input, 0, sizeof(input));
    input.version = 1;
    input.hook_id = LHA_HOOK_FILE_OPEN;
    input.ts_ns = 212;
    input.ret = 0;
    input.policy_state = LHA_POLICY_INFERRED_ALLOW;
    input.subject.task = (const void *)2;
    input.subject.cred = (const void *)2;
    input.args.file_open.file = (const void *)1;

    assert(lha_resolve_event(ops, &input, &output) == 0);
    assert(strcmp(output.result.runtime_result, "allow") == 0);
    assert(strcmp(output.result.policy_result, "inferred_allow") == 0);
}

static void test_file_open(const struct lha_kernel_ops *ops)
{
    struct lha_enriched_event_v1 output;
    char json[2048];

    prepare_file_open_event(ops, &output);
    assert(output.subject.tid == 5302u);
    assert(strcmp(output.subject.scontext, "u:r:subject_async_t:s0") == 0);
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
    input.subject.task = (const void *)3;
    input.subject.cred = (const void *)1;
    input.args.file_permission.file = (const void *)2;
    input.args.file_permission.mask = LHA_MAY_WRITE;

    assert(lha_resolve_event(ops, &input, &output) == 0);
    assert(strcmp(output.subject.scontext, "u:r:subject_alt_t:s0") == 0);
    assert(strcmp(output.request.perm, "append") == 0);
    assert(strcmp(output.result.runtime_result, "deny") == 0);
    assert(strcmp(output.result.policy_result, "deny") == 0);
}

static void test_avc_match_deny(const struct lha_kernel_ops *ops)
{
    struct lha_enriched_event_v1 output;
    struct lha_avc_event_v1 avc;
    struct lha_avc_match_options options;

    prepare_file_open_event(ops, &output);
    memset(&avc, 0, sizeof(avc));
    memset(&options, 0, sizeof(options));

    avc.timestamp_ns = output.timestamp_ns + 1000;
    avc.pid = output.subject.pid;
    avc.tid = output.subject.tid;
    snprintf(avc.comm, sizeof(avc.comm), "%s", output.subject.comm);
    snprintf(avc.scontext, sizeof(avc.scontext), "%s", output.subject.scontext);
    snprintf(avc.tcontext, sizeof(avc.tcontext), "%s", output.target.tcontext);
    snprintf(avc.tclass, sizeof(avc.tclass), "%s", output.target.tclass);
    snprintf(avc.perm, sizeof(avc.perm), "%s", "open");
    avc.permissive = 1;
    avc.denied = 1;
    options.window_ns = 50000;

    assert(lha_apply_avc_policy_result(&output, &avc, 1, &options) == 0);
    assert(strcmp(output.result.runtime_result, "allow") == 0);
    assert(strcmp(output.result.policy_result, "deny") == 0);
}

static void test_avc_inferred_allow(const struct lha_kernel_ops *ops)
{
    struct lha_enriched_event_v1 output;

    prepare_file_open_event(ops, &output);
    assert(lha_apply_avc_policy_result(&output, NULL, 0, NULL) == 0);
    assert(strcmp(output.result.policy_result, "inferred_allow") == 0);
}

static void test_avc_unknown_missing_keys(const struct lha_kernel_ops *ops)
{
    struct lha_enriched_event_v1 output;

    prepare_file_open_event(ops, &output);
    output.target.tcontext[0] = '\0';
    assert(lha_apply_avc_policy_result(&output, NULL, 0, NULL) == 0);
    assert(strcmp(output.result.policy_result, "unknown") == 0);
}

static void test_avc_ambiguous_match(const struct lha_kernel_ops *ops)
{
    struct lha_enriched_event_v1 output;
    struct lha_avc_event_v1 avc[2];

    prepare_file_open_event(ops, &output);
    memset(avc, 0, sizeof(avc));

    for (size_t i = 0; i < 2; ++i) {
        avc[i].timestamp_ns = output.timestamp_ns + 1000;
        snprintf(avc[i].scontext, sizeof(avc[i].scontext), "%s", output.subject.scontext);
        snprintf(avc[i].tcontext, sizeof(avc[i].tcontext), "%s", output.target.tcontext);
        snprintf(avc[i].tclass, sizeof(avc[i].tclass), "%s", output.target.tclass);
        snprintf(avc[i].perm, sizeof(avc[i].perm), "%s", "open");
        avc[i].denied = 1;
    }

    assert(lha_apply_avc_policy_result(&output, avc, 2, NULL) == 0);
    assert(strcmp(output.result.policy_result, "unknown") == 0);
}

int main(void)
{
    struct lha_kernel_ops ops;

    memset(&ops, 0, sizeof(ops));
    ops.resolve_subject = mock_resolve_subject;
    ops.resolve_inode = mock_resolve_inode;
    ops.resolve_file = mock_resolve_file;
    ops.sid_to_context = mock_sid_to_context;
    ops.sclass_to_string = mock_sclass_to_string;
    ops.resolve_policy_result = mock_policy_result;

    test_inode_permission(&ops);
    test_policy_state_override(&ops);
    test_policy_state_inferred_allow(&ops);
    test_file_open(&ops);
    test_file_permission(&ops);
    test_avc_match_deny(&ops);
    test_avc_inferred_allow(&ops);
    test_avc_unknown_missing_keys(&ops);
    test_avc_ambiguous_match(&ops);

    puts("ok");
    return 0;
}
