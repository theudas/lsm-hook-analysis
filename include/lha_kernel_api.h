#ifndef LHA_KERNEL_API_H
#define LHA_KERNEL_API_H

#include <stddef.h>
#include <stdint.h>

#include "lha_types.h"

/*
 * 这层接口负责把真实内核对象翻译成 resolver 需要的原始字段。
 * core resolver 不直接依赖具体内核头文件，方便先把事件模型和
 * 路由逻辑开发稳定，再接入真正的内核实现。
 */

struct lha_subject_raw {
    uint32_t pid;
    uint32_t tid;
    uint32_t sid;
    char comm[LHA_MAX_COMM_LEN];
};

struct lha_inode_raw {
    uint32_t mode;
    uint64_t ino;
    uint16_t sclass;
    uint32_t sid;
    char dev[LHA_MAX_DEV_LEN];
    char path[LHA_MAX_PATH_LEN];
};

struct lha_file_raw {
    struct lha_inode_raw inode;
    uint32_t f_flags;
    uint32_t f_mode;
};

struct lha_kernel_ops {
    int (*resolve_subject)(const void *task,
                           const void *cred,
                           uint64_t ts_ns,
                           struct lha_subject_raw *subject);
    int (*resolve_inode)(const void *inode, uint64_t ts_ns, struct lha_inode_raw *target);
    int (*resolve_file)(const void *file, uint64_t ts_ns, struct lha_file_raw *target);
    int (*sid_to_context)(uint32_t sid, char *buf, size_t buf_len);
    int (*sclass_to_string)(uint16_t sclass, char *buf, size_t buf_len);
    int (*resolve_policy_result)(const struct lha_capture_event_v1 *event,
                                 char *buf,
                                 size_t buf_len);
};

#endif
