#include "lha_centos9_resolver.h"

#include <linux/bits.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/tracepoint.h>

#define LHA_SELINUX_TP_NAME "selinux_audited"

#define LHA_SELINUX_PERM_READ    BIT(1)
#define LHA_SELINUX_PERM_WRITE   BIT(2)
#define LHA_SELINUX_PERM_APPEND  BIT(9)
#define LHA_SELINUX_PERM_EXECUTE BIT(14)
#define LHA_SELINUX_PERM_OPEN    BIT(18)
#define LHA_SELINUX_DIR_SEARCH   BIT(28)

/*
 * This mirrors security/selinux/include/avc.h in CentOS Stream 9.  The
 * tracepoint passes this pointer directly, but the private SELinux header is
 * not available to a standalone module built from this repository.
 */
struct lha_selinux_audit_data {
	u32 ssid;
	u32 tsid;
	u16 tclass;
	u32 requested;
	u32 audited;
	u32 denied;
	int result;
	void *state;
};

static struct tracepoint *lha_avc_tracepoint;
static bool lha_avc_capture_debug;

module_param_named(debug_capture, lha_avc_capture_debug, bool, 0644);
MODULE_PARM_DESC(debug_capture,
		 "Log captured SELinux AVC deny events before they are forwarded to the resolver");

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

static void lha_decode_avc_perm(const char *tclass, u32 denied,
				char *buf, size_t buf_len)
{
	if (!buf || buf_len == 0)
		return;

	buf[0] = '\0';
	if (denied & LHA_SELINUX_PERM_OPEN)
		lha_append_perm(buf, buf_len, "open");
	if (denied & LHA_SELINUX_PERM_READ)
		lha_append_perm(buf, buf_len, "read");
	if (denied & LHA_SELINUX_PERM_APPEND)
		lha_append_perm(buf, buf_len, "append");
	else if (denied & LHA_SELINUX_PERM_WRITE)
		lha_append_perm(buf, buf_len, "write");
	if (tclass && strcmp(tclass, "dir") == 0) {
		if (denied & LHA_SELINUX_DIR_SEARCH)
			lha_append_perm(buf, buf_len, "search");
	} else if (denied & LHA_SELINUX_PERM_EXECUTE) {
		lha_append_perm(buf, buf_len, "exec");
	}
}

static void lha_avc_trace_probe(void *data,
				struct lha_selinux_audit_data *sad,
				char *scontext,
				char *tcontext,
				const char *tclass)
{
	struct lha_avc_event_v1 event;
	int rc;

	(void)data;

	if (!sad || sad->denied == 0)
		return;

	memset(&event, 0, sizeof(event));
	event.timestamp_ns = ktime_get_real_ns();
	event.pid = task_tgid_nr(current);
	event.tid = task_pid_nr(current);
	event.denied = 1;
	event.permissive = sad->result == 0;

	lha_copy_string(event.comm, sizeof(event.comm), current->comm);
	lha_copy_string(event.scontext, sizeof(event.scontext), scontext);
	lha_copy_string(event.tcontext, sizeof(event.tcontext), tcontext);
	lha_copy_string(event.tclass, sizeof(event.tclass), tclass);
	lha_decode_avc_perm(tclass, sad->denied, event.perm, sizeof(event.perm));

	if (lha_avc_capture_debug)
		pr_info("lha_centos9_avc_capture: captured avc deny pid=%u tid=%u comm=%s permissive=%u tclass=%s perm=%s scontext=%s tcontext=%s\n",
			event.pid, event.tid, event.comm, event.permissive,
			event.tclass, event.perm, event.scontext, event.tcontext);

	rc = lha_centos9_record_avc_event(&event);
	if (lha_avc_capture_debug) {
		if (rc == 0)
			pr_info("lha_centos9_avc_capture: forwarded avc deny to resolver cache pid=%u tid=%u comm=%s perm=%s\n",
				event.pid, event.tid, event.comm, event.perm);
		else
			pr_warn("lha_centos9_avc_capture: failed to forward avc deny to resolver cache: %d\n",
				rc);
	}
}

static void lha_find_tracepoint(struct tracepoint *tp, void *priv)
{
	struct tracepoint **found = priv;

	if (*found)
		return;
	if (strcmp(tp->name, LHA_SELINUX_TP_NAME) == 0)
		*found = tp;
}

static int __init lha_centos9_avc_capture_init(void)
{
	int rc;

	for_each_kernel_tracepoint(lha_find_tracepoint, &lha_avc_tracepoint);
	if (!lha_avc_tracepoint) {
		pr_err("lha_centos9_avc_capture: tracepoint %s not found\n",
		       LHA_SELINUX_TP_NAME);
		return -ENOENT;
	}

	rc = tracepoint_probe_register(lha_avc_tracepoint, lha_avc_trace_probe,
				       NULL);
	if (rc) {
		pr_err("lha_centos9_avc_capture: failed to register tracepoint: %d\n",
		       rc);
		lha_avc_tracepoint = NULL;
		return rc;
	}

	pr_info("lha_centos9_avc_capture loaded\n");
	return 0;
}

static void __exit lha_centos9_avc_capture_exit(void)
{
	if (lha_avc_tracepoint) {
		tracepoint_probe_unregister(lha_avc_tracepoint,
					    lha_avc_trace_probe, NULL);
		tracepoint_synchronize_unregister();
		lha_avc_tracepoint = NULL;
	}
	pr_info("lha_centos9_avc_capture unloaded\n");
}

module_init(lha_centos9_avc_capture_init);
module_exit(lha_centos9_avc_capture_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI Codex");
MODULE_DESCRIPTION("CentOS Stream 9 SELinux AVC capture module for LHA resolver");
MODULE_SOFTDEP("pre: lha_centos9_resolver");
