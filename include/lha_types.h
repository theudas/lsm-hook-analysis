#ifndef LHA_TYPES_H
#define LHA_TYPES_H

#include <stddef.h>
#include <stdint.h>

#define LHA_MAX_COMM_LEN 16
#define LHA_MAX_CONTEXT_LEN 256
#define LHA_MAX_DEV_LEN 32
#define LHA_MAX_TYPE_LEN 16
#define LHA_MAX_PATH_LEN 512
#define LHA_MAX_PERM_LEN 64
#define LHA_MAX_HOOK_LEN 64
#define LHA_MAX_SIG_LEN 128
#define LHA_MAX_RESULT_LEN 16

#define LHA_MAY_EXEC   0x00000001
#define LHA_MAY_WRITE  0x00000002
#define LHA_MAY_READ   0x00000004
#define LHA_MAY_APPEND 0x00000008
#define LHA_MAY_OPEN   0x00000020

#define LHA_FILE_MODE_READ  0x00000001u
#define LHA_FILE_MODE_WRITE 0x00000002u
#define LHA_FILE_MODE_EXEC  0x00000004u

enum lha_hook_id {
    LHA_HOOK_INODE_PERMISSION = 1,
    LHA_HOOK_FILE_OPEN = 2,
    LHA_HOOK_FILE_PERMISSION = 3,
};

enum lha_policy_state {
    LHA_POLICY_UNKNOWN = 0,
    LHA_POLICY_ALLOW = 1,
    LHA_POLICY_DENY = 2,
};

struct lha_capture_event_v1 {
    uint16_t version;
    uint16_t hook_id;
    uint64_t ts_ns;
    int32_t ret;
    uint8_t policy_state;
    uint8_t reserved[3];
    struct {
        const void *task;
        const void *cred;
    } subject;
    union {
        struct {
            const void *inode;
            int32_t mask;
        } inode_permission;
        struct {
            const void *file;
        } file_open;
        struct {
            const void *file;
            int32_t mask;
        } file_permission;
    } args;
};

struct lha_subject_v1 {
    uint32_t pid;
    uint32_t tid;
    char scontext[LHA_MAX_CONTEXT_LEN];
    char comm[LHA_MAX_COMM_LEN];
};

struct lha_request_v1 {
    int32_t mask_raw;
    char obj_type[LHA_MAX_TYPE_LEN];
    char perm[LHA_MAX_PERM_LEN];
};

struct lha_target_v1 {
    char dev[LHA_MAX_DEV_LEN];
    uint64_t ino;
    char type[LHA_MAX_TYPE_LEN];
    char path[LHA_MAX_PATH_LEN];
    char tclass[LHA_MAX_TYPE_LEN];
    char tcontext[LHA_MAX_CONTEXT_LEN];
};

struct lha_result_v1 {
    int32_t ret;
    char runtime_result[LHA_MAX_RESULT_LEN];
    char policy_result[LHA_MAX_RESULT_LEN];
};

struct lha_enriched_event_v1 {
    uint16_t version;
    uint16_t hook_id;
    uint64_t timestamp_ns;
    char hook[LHA_MAX_HOOK_LEN];
    char hook_signature[LHA_MAX_SIG_LEN];
    struct lha_subject_v1 subject;
    struct lha_request_v1 request;
    struct lha_target_v1 target;
    struct lha_result_v1 result;
};

#endif
