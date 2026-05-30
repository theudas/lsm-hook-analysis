/*
 * lha_centos9_capture.c — kprobe-based real LSM hook capture module
 *
 * Hooks selinux_inode_permission / selinux_file_open / selinux_file_permission
 * at function entry via kprobe (NOT kretprobe), captures parameters, then
 * dispatches to the resolver via a private workqueue for enrichment and
 * event streaming.
 *
 * We deliberately avoid kretprobe because aarch64 kernels with Shadow Call
 * Stack (CONFIG_SHADOW_CALL_STACK) and Pointer Authentication
 * (CONFIG_ARM64_PTR_AUTH_KERNEL) can crash when kretprobe rewrites LR (x30).
 * Since we only probe function entry, no return-address manipulation occurs.
 *
 * Trade-off: without kretprobe we cannot observe the hook return value, so
 * ret is always recorded as 0 (allow).  The resolver's AVC correlation
 * (via lha_centos9_avc_capture.ko) still correctly reports policy_result
 * as deny / inferred_allow / unknown.
 */

#include "lha_centos9_resolver.h"

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

/*
 * Architecture-portable kprobe argument access.
 * x86_64: di, si, dx, ...
 * aarch64: regs[0], regs[1], regs[2], ...
 */
#if defined(CONFIG_X86_64)
#define LHA_ARG0(regs) ((regs)->di)
#define LHA_ARG1(regs) ((regs)->si)
#elif defined(CONFIG_ARM64)
#define LHA_ARG0(regs) ((regs)->regs[0])
#define LHA_ARG1(regs) ((regs)->regs[1])
#else
#error "Unsupported architecture for lha_centos9_capture"
#endif

#define LHA_CAPTURE_DEFAULT_MAX_PENDING 4096

static unsigned int lha_capture_max_pending = LHA_CAPTURE_DEFAULT_MAX_PENDING;
module_param_named(max_pending, lha_capture_max_pending, uint, 0644);
MODULE_PARM_DESC(max_pending,
		 "Maximum number of events queued for resolver processing");

static atomic_t lha_pending_count = ATOMIC_INIT(0);
static struct workqueue_struct *lha_capture_wq;

/*
 * Suppress recursive probing: when the resolver runs (d_path, getsecctx,
 * etc.) it may trigger the very hooks we probe.  A global atomic counter
 * prevents the entry handlers from queueing events while any worker is
 * inside resolve_event().
 */
static atomic_t lha_suppress_count = ATOMIC_INIT(0);

/* Workqueue item wrapping a fully-assembled capture event. */
struct lha_pending_event {
	struct work_struct work;
	struct lha_capture_event_v1 ev;
};

/* ------------------------------------------------------------------ */
/* Ref helpers                                                         */
/* ------------------------------------------------------------------ */

static void lha_release_capture_refs(struct lha_capture_event_v1 *ev)
{
	switch (ev->hook_id) {
	case LHA_HOOK_INODE_PERMISSION:
		if (ev->args.inode_permission.inode)
			iput(ev->args.inode_permission.inode);
		break;
	case LHA_HOOK_FILE_OPEN:
		if (ev->args.file_open.file)
			fput(ev->args.file_open.file);
		break;
	case LHA_HOOK_FILE_PERMISSION:
		if (ev->args.file_permission.file)
			fput(ev->args.file_permission.file);
		break;
	default:
		break;
	}
	if (ev->subject.task)
		put_task_struct(ev->subject.task);
	if (ev->subject.cred)
		put_cred(ev->subject.cred);
}

/* ------------------------------------------------------------------ */
/* Workqueue worker: runs in sleepable context                         */
/* ------------------------------------------------------------------ */

static void lha_capture_worker(struct work_struct *work)
{
	struct lha_pending_event *pending =
		container_of(work, struct lha_pending_event, work);
	struct lha_enriched_event_v1 *out;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (out) {
		atomic_inc(&lha_suppress_count);
		lha_centos9_resolve_event(&pending->ev, out);
		atomic_dec(&lha_suppress_count);
		kfree(out);
	}

	lha_release_capture_refs(&pending->ev);
	kfree(pending);
	atomic_dec(&lha_pending_count);
}

/* ------------------------------------------------------------------ */
/* Common: queue a capture event from kprobe handler (atomic ctx)      */
/* ------------------------------------------------------------------ */

static void lha_submit_event(struct lha_capture_event_v1 *ev)
{
	struct lha_pending_event *pending;

	if (atomic_read(&lha_pending_count) >=
	    (int)READ_ONCE(lha_capture_max_pending))
		goto drop;

	pending = kzalloc(sizeof(*pending), GFP_ATOMIC);
	if (!pending)
		goto drop;

	INIT_WORK(&pending->work, lha_capture_worker);
	pending->ev = *ev;
	atomic_inc(&lha_pending_count);
	queue_work(lha_capture_wq, &pending->work);
	return;

drop:
	lha_release_capture_refs(ev);
}

/* ================================================================== */
/* kprobe: selinux_inode_permission(struct inode *inode, int mask)     */
/* ================================================================== */

static int lha_inode_perm_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct lha_capture_event_v1 ev;
	struct inode *inode = (struct inode *)LHA_ARG0(regs);
	int mask = (int)LHA_ARG1(regs);

	if (atomic_read(&lha_suppress_count))
		return 0;

	if (!inode)
		return 0;

	memset(&ev, 0, sizeof(ev));
	ev.version = 1;
	ev.hook_id = LHA_HOOK_INODE_PERMISSION;
	ev.ts_ns = ktime_get_real_ns();
	ev.ret = 0;

	ev.args.inode_permission.inode = igrab(inode);
	if (!ev.args.inode_permission.inode)
		return 0;

	ev.args.inode_permission.mask = mask;
	ev.subject.task = get_task_struct(current);
	ev.subject.cred = get_current_cred();

	lha_submit_event(&ev);
	return 0;
}

static struct kprobe lha_inode_perm_kprobe = {
	.symbol_name = "selinux_inode_permission",
	.pre_handler = lha_inode_perm_handler,
};

/* ================================================================== */
/* kprobe: selinux_file_open(struct file *file)                       */
/* ================================================================== */

static int lha_file_open_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct lha_capture_event_v1 ev;
	struct file *file = (struct file *)LHA_ARG0(regs);

	if (atomic_read(&lha_suppress_count))
		return 0;

	if (!file || IS_ERR(file))
		return 0;

	memset(&ev, 0, sizeof(ev));
	ev.version = 1;
	ev.hook_id = LHA_HOOK_FILE_OPEN;
	ev.ts_ns = ktime_get_real_ns();
	ev.ret = 0;

	get_file(file);
	ev.args.file_open.file = file;
	ev.subject.task = get_task_struct(current);
	ev.subject.cred = get_current_cred();

	lha_submit_event(&ev);
	return 0;
}

static struct kprobe lha_file_open_kprobe = {
	.symbol_name = "selinux_file_open",
	.pre_handler = lha_file_open_handler,
};

/* ================================================================== */
/* kprobe: selinux_file_permission(struct file *file, int mask)       */
/* ================================================================== */

static int lha_file_perm_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct lha_capture_event_v1 ev;
	struct file *file = (struct file *)LHA_ARG0(regs);
	int mask = (int)LHA_ARG1(regs);

	if (atomic_read(&lha_suppress_count))
		return 0;

	if (!file || IS_ERR(file))
		return 0;

	memset(&ev, 0, sizeof(ev));
	ev.version = 1;
	ev.hook_id = LHA_HOOK_FILE_PERMISSION;
	ev.ts_ns = ktime_get_real_ns();
	ev.ret = 0;

	get_file(file);
	ev.args.file_permission.file = file;
	ev.args.file_permission.mask = mask;
	ev.subject.task = get_task_struct(current);
	ev.subject.cred = get_current_cred();

	lha_submit_event(&ev);
	return 0;
}

static struct kprobe lha_file_perm_kprobe = {
	.symbol_name = "selinux_file_permission",
	.pre_handler = lha_file_perm_handler,
};

/* ================================================================== */
/* Module init / exit                                                  */
/* ================================================================== */

static struct kprobe *lha_kprobes[] = {
	&lha_inode_perm_kprobe,
	&lha_file_open_kprobe,
	&lha_file_perm_kprobe,
};

static int __init lha_centos9_capture_init(void)
{
	int rc;

	lha_capture_wq = alloc_workqueue("lha_capture", WQ_UNBOUND, 0);
	if (!lha_capture_wq)
		return -ENOMEM;

	rc = register_kprobes(lha_kprobes, ARRAY_SIZE(lha_kprobes));
	if (rc) {
		pr_err("lha_centos9_capture: failed to register kprobes: %d\n",
		       rc);
		destroy_workqueue(lha_capture_wq);
		return rc;
	}

	pr_info("lha_centos9_capture: loaded, hooking 3 SELinux functions (max_pending=%u)\n",
		lha_capture_max_pending);
	return 0;
}

static void __exit lha_centos9_capture_exit(void)
{
	unregister_kprobes(lha_kprobes, ARRAY_SIZE(lha_kprobes));
	destroy_workqueue(lha_capture_wq);

	pr_info("lha_centos9_capture: unloaded (missed: inode_perm=%lu file_open=%lu file_perm=%lu)\n",
		lha_inode_perm_kprobe.nmissed,
		lha_file_open_kprobe.nmissed,
		lha_file_perm_kprobe.nmissed);
}

module_init(lha_centos9_capture_init);
module_exit(lha_centos9_capture_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lha-team");
MODULE_DESCRIPTION("CentOS Stream 9 kprobe-based LSM hook capture module");
MODULE_SOFTDEP("pre: lha_centos9_resolver");
