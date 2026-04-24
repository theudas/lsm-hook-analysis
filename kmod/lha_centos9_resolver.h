#ifndef LHA_CENTOS9_RESOLVER_H
#define LHA_CENTOS9_RESOLVER_H

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/types.h>

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

enum lha_hook_id {
	LHA_HOOK_INODE_PERMISSION = 1,
	LHA_HOOK_FILE_OPEN = 2,
	LHA_HOOK_FILE_PERMISSION = 3,
};

enum lha_policy_state {
	LHA_POLICY_UNKNOWN = 0,
	LHA_POLICY_ALLOW = 1,
	LHA_POLICY_DENY = 2,
	LHA_POLICY_INFERRED_ALLOW = 3,
};

struct lha_capture_event_v1 {
	__u16 version;
	__u16 hook_id;
	__u64 ts_ns;
	__s32 ret;
	__u8 policy_state;
	__u8 reserved[3];
	struct {
		struct task_struct *task;
		const struct cred *cred;
	} subject;
	union {
		struct {
			struct inode *inode;
			__s32 mask;
		} inode_permission;
		struct {
			struct file *file;
		} file_open;
		struct {
			struct file *file;
			__s32 mask;
		} file_permission;
	} args;
};

struct lha_subject_v1 {
	__u32 pid;
	__u32 tid;
	char scontext[LHA_MAX_CONTEXT_LEN];
	char comm[LHA_MAX_COMM_LEN];
};

struct lha_request_v1 {
	__s32 mask_raw;
	char obj_type[LHA_MAX_TYPE_LEN];
	char perm[LHA_MAX_PERM_LEN];
};

struct lha_target_v1 {
	char dev[LHA_MAX_DEV_LEN];
	__u64 ino;
	char type[LHA_MAX_TYPE_LEN];
	char path[LHA_MAX_PATH_LEN];
	char tclass[LHA_MAX_TYPE_LEN];
	char tcontext[LHA_MAX_CONTEXT_LEN];
};

struct lha_result_v1 {
	__s32 ret;
	char runtime_result[LHA_MAX_RESULT_LEN];
	char policy_result[LHA_MAX_RESULT_LEN];
};

struct lha_enriched_event_v1 {
	__u16 version;
	__u16 hook_id;
	__u64 timestamp_ns;
	char hook[LHA_MAX_HOOK_LEN];
	char hook_signature[LHA_MAX_SIG_LEN];
	struct lha_subject_v1 subject;
	struct lha_request_v1 request;
	struct lha_target_v1 target;
	struct lha_result_v1 result;
};

/*
 * 外部抓取方必须在 hook 现场为下面这些对象建立稳定引用，再把它们传给 resolver：
 * - task: 例如 get_task_struct()
 * - cred: 例如 get_cred()
 * - inode: 例如 ihold()/igrab()
 * - file: 例如 get_file()
 *
 * 该 resolver 设计为在可睡眠的内核上下文中运行，例如 workqueue/kthread。
 * 不建议在原始 hook 回调的任何不可睡眠上下文里直接调用它，因为
 * security_secid_to_secctx()/security_inode_getsecctx()/d_path() 都可能睡眠。
 */
int lha_centos9_resolve_event(const struct lha_capture_event_v1 *in,
			      struct lha_enriched_event_v1 *out);

int lha_centos9_format_json(const struct lha_enriched_event_v1 *event,
			    char *buf,
			    size_t buf_len);

#endif
