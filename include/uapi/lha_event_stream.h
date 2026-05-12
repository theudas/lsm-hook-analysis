#ifndef LHA_EVENT_STREAM_H
#define LHA_EVENT_STREAM_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
#endif

#define LHA_MAX_COMM_LEN 16
#define LHA_MAX_CONTEXT_LEN 256
#define LHA_MAX_DEV_LEN 32
#define LHA_MAX_TYPE_LEN 16
#define LHA_MAX_PATH_LEN 512
#define LHA_MAX_PERM_LEN 64
#define LHA_MAX_HOOK_LEN 64
#define LHA_MAX_SIG_LEN 128
#define LHA_MAX_RESULT_LEN 16

#define LHA_EVENT_STREAM_MAGIC       0x4c484145U
#define LHA_EVENT_STREAM_ABI_V1      1
#define LHA_EVENT_STREAM_PAYLOAD_V1  1
#define LHA_EVENT_STREAM_DEVICE_NAME "lha_centos9_event_stream"

enum lha_event_frame_type {
	LHA_EVENT_FRAME_DATA = 1,
};

struct lha_event_frame_hdr_v1 {
	__u32 magic; // 事件帧魔数，用于校验这是不是合法帧
	__u16 abi_version; // 事件流通道 ABI 版本
	__u16 frame_type; // 帧类型，当前为数据帧
	__u16 header_len; // 帧头长度
	__u16 payload_version; // 载荷结构版本
	__u32 payload_len; // 载荷长度
	__u64 seq; // 事件序号，用于检测丢包和断档
	__u64 emitted_ns; // 事件写入通道时的时间戳
	__u32 flags; // 标志位，当前预留
	__u32 reserved0; // 预留字段
};

struct lha_event_subject_v1 {
	__u32 pid; // 进程 pid
	__u32 tid; // 线程 tid
	char scontext[LHA_MAX_CONTEXT_LEN]; // 主体的 SELinux context
	char comm[LHA_MAX_COMM_LEN]; // 进程名
};

struct lha_event_request_v1 {
	__s32 mask_raw; // 原始访问 mask
	char obj_type[LHA_MAX_TYPE_LEN]; // 目标对象类型，例如 reg/dir
	char perm[LHA_MAX_PERM_LEN]; // 解析后的权限字符串
};

struct lha_event_target_v1 {
	char dev[LHA_MAX_DEV_LEN]; // 目标所在设备标识
	__u64 ino; // 目标 inode 号
	char type[LHA_MAX_TYPE_LEN]; // 目标对象类型，例如 reg/dir
	char path[LHA_MAX_PATH_LEN]; // 目标路径
	char tclass[LHA_MAX_TYPE_LEN]; // 目标对象安全类
	char tcontext[LHA_MAX_CONTEXT_LEN]; // 目标的 SELinux context
};

struct lha_event_result_v1 {
	__s32 ret; // 原始 hook 返回值
	char runtime_result[LHA_MAX_RESULT_LEN]; // 运行时结果，例如 allow/deny/error
	char policy_result[LHA_MAX_RESULT_LEN]; // 策略结果，例如 deny/inferred_allow/unknown
};

struct lha_event_payload_v1 {
	__u16 version; // 事件载荷版本，当前固定填 1
	__u16 hook_id; // 事件来源的 LSM hook 类型
	__u64 timestamp_ns; // 原始 LSM hook 事件时间戳
	char hook[LHA_MAX_HOOK_LEN]; // hook 名称字符串
	char hook_signature[LHA_MAX_SIG_LEN]; // hook 函数原型字符串
	struct lha_event_subject_v1 subject; // 访问主体信息
	struct lha_event_request_v1 request; // 请求语义信息
	struct lha_event_target_v1 target; // 访问目标信息
	struct lha_event_result_v1 result; // 运行结果和策略结果
};

struct lha_event_frame_v1 {
	struct lha_event_frame_hdr_v1 hdr; // channel 传输元数据
	struct lha_event_payload_v1 payload; // 结构化 lsm hook 事件内容
};

#endif
