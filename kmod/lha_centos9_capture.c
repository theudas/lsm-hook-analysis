/*
 * lha_centos9_capture.c — kprobe-based real LSM hook capture module
 *
 * Probes selinux_file_open() at function entry via kprobe, captures the
 * struct file argument, then dispatches to the resolver via a private
 * workqueue for enrichment and event streaming.
 *
 * Why only selinux_file_open?
 * ---------------------------
 * Earlier revisions also probed selinux_inode_permission and
 * selinux_file_permission.  Loading that variant reliably HARD-REBOOTED
 * CentOS Stream 9 on aarch64 (5.14.0-694.el9.aarch64) the instant the probes
 * armed.  Those two hooks are the hottest LSM callbacks in the kernel:
 *
 *   - selinux_inode_permission fires on *every* path-walk component, and is
 *     invoked in RCU-walk (MAY_NOT_BLOCK) context.
 *   - selinux_file_permission fires on *every* read()/write()/sendfile().
 *
 * Running a GFP_ATOMIC allocation + reference grabs + queue_work() from the
 * kprobe atomic / IRQ-disabled context at full syscall rate drives the
 * machine straight into a lockup/panic.  selinux_file_open, by contrast,
 * fires once per open() in a clean, sleepable process context and still
 * yields the full path, the requested open permissions, the subject identity
 * and AVC deny correlation.  The experiment and full rationale are written up
 * in docs/capture_hook_selection.md.
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
#elif defined(CONFIG_ARM64)
#define LHA_ARG0(regs) ((regs)->regs[0])
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
 * etc.) it may, via memory reclaim, trigger the very hook we probe.  A global
 * atomic counter prevents the entry handler from queueing events while any
 * worker is inside resolve_event().
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

	/* References are released here, in sleepable context only. */
	lha_release_capture_refs(&pending->ev);
	kfree(pending);
	atomic_dec(&lha_pending_count);
}

/* ================================================================== */
/* kprobe: selinux_file_open(struct file *file)                       */
/* ================================================================== */

/*
 * The kprobe pre-handler runs in atomic / IRQ-disabled context.  It must
 * never release a captured reference, because iput() can sleep and fput()
 * defers to task work — both are unsafe / undesirable on a hot drop path.
 *
 * To guarantee that, we acquire NO reference until the queue slot and the
 * pending event have both been secured.  Every drop path below this point
 * bails out *before* taking a reference; references are therefore released
 * exclusively by the sleepable worker.
 */
static int lha_file_open_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)LHA_ARG0(regs);
	struct lha_pending_event *pending;

	if (atomic_read(&lha_suppress_count))
		return 0;

	if (!file || IS_ERR(file))
		return 0;

	if (atomic_read(&lha_pending_count) >=
	    (int)READ_ONCE(lha_capture_max_pending))
		return 0;

	pending = kzalloc(sizeof(*pending), GFP_ATOMIC);
	if (!pending)
		return 0;

	INIT_WORK(&pending->work, lha_capture_worker);
	pending->ev.version = 1;
	pending->ev.hook_id = LHA_HOOK_FILE_OPEN;
	pending->ev.ts_ns = ktime_get_real_ns();
	pending->ev.ret = 0;

	get_file(file);
	pending->ev.args.file_open.file = file;
	pending->ev.subject.task = get_task_struct(current);
	pending->ev.subject.cred = get_current_cred();

	atomic_inc(&lha_pending_count);
	queue_work(lha_capture_wq, &pending->work);
	return 0;
}

static struct kprobe lha_file_open_kprobe = {
	.symbol_name = "selinux_file_open",
	.pre_handler = lha_file_open_handler,
};

/* ================================================================== */
/* Module init / exit                                                  */
/* ================================================================== */

static int __init lha_centos9_capture_init(void)
{
	int rc;

	lha_capture_wq = alloc_workqueue("lha_capture", WQ_UNBOUND, 0);
	if (!lha_capture_wq)
		return -ENOMEM;

	rc = register_kprobe(&lha_file_open_kprobe);
	if (rc) {
		pr_err("lha_centos9_capture: failed to register kprobe on selinux_file_open: %d\n",
		       rc);
		destroy_workqueue(lha_capture_wq);
		return rc;
	}

	pr_info("lha_centos9_capture: loaded, hooking selinux_file_open (max_pending=%u)\n",
		lha_capture_max_pending);
	return 0;
}

static void __exit lha_centos9_capture_exit(void)
{
	/*
	 * unregister_kprobe() guarantees the handler is no longer running and
	 * will not start again.  destroy_workqueue() then drains any work that
	 * was already queued, so every captured file reference is released
	 * before the module unloads.
	 */
	unregister_kprobe(&lha_file_open_kprobe);
	destroy_workqueue(lha_capture_wq);

	pr_info("lha_centos9_capture: unloaded (missed file_open=%lu)\n",
		lha_file_open_kprobe.nmissed);
}

module_init(lha_centos9_capture_init);
module_exit(lha_centos9_capture_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lha-team");
MODULE_DESCRIPTION("CentOS Stream 9 kprobe-based LSM hook capture module (selinux_file_open)");
MODULE_SOFTDEP("pre: lha_centos9_resolver");
