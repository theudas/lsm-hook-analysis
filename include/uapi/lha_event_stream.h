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
	__u32 magic;
	__u16 abi_version;
	__u16 frame_type;
	__u16 header_len;
	__u16 payload_version;
	__u32 payload_len;
	__u64 seq;
	__u64 emitted_ns;
	__u32 flags;
	__u32 reserved0;
};

struct lha_event_subject_v1 {
	__u32 pid;
	__u32 tid;
	char scontext[LHA_MAX_CONTEXT_LEN];
	char comm[LHA_MAX_COMM_LEN];
};

struct lha_event_request_v1 {
	__s32 mask_raw;
	char obj_type[LHA_MAX_TYPE_LEN];
	char perm[LHA_MAX_PERM_LEN];
};

struct lha_event_target_v1 {
	char dev[LHA_MAX_DEV_LEN];
	__u64 ino;
	char type[LHA_MAX_TYPE_LEN];
	char path[LHA_MAX_PATH_LEN];
	char tclass[LHA_MAX_TYPE_LEN];
	char tcontext[LHA_MAX_CONTEXT_LEN];
};

struct lha_event_result_v1 {
	__s32 ret;
	char runtime_result[LHA_MAX_RESULT_LEN];
	char policy_result[LHA_MAX_RESULT_LEN];
};

struct lha_event_payload_v1 {
	__u16 version;
	__u16 hook_id;
	__u64 timestamp_ns;
	char hook[LHA_MAX_HOOK_LEN];
	char hook_signature[LHA_MAX_SIG_LEN];
	struct lha_event_subject_v1 subject;
	struct lha_event_request_v1 request;
	struct lha_event_target_v1 target;
	struct lha_event_result_v1 result;
};

struct lha_event_frame_v1 {
	struct lha_event_frame_hdr_v1 hdr;
	struct lha_event_payload_v1 payload;
};

#endif
