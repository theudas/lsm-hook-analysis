/*
 * lha_centos9_capture.c — kretprobe-based real LSM hook capture module
 *
 * Hooks selinux_inode_permission / selinux_file_open / selinux_file_permission,
 * captures parameters and return values, then dispatches to the resolver via
 * workqueue for enrichment and event streaming.
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
 * Architecture-portable kretprobe argument access.
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

/*
 * Per-kretprobe-instance data saved in the entry handler and consumed in
 * the return handler.
 */
struct lha_capture_data {
	__u16 hook_id;
	__u64 ts_ns;
	struct task_struct *task;
	const struct cred *cred;
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
	bool refs_valid;
};

/* Workqueue item wrapping a fully-assembled capture event. */
struct lha_pending_event {
	struct work_struct work;
	struct lha_capture_event_v1 ev;
};

/* ------------------------------------------------------------------ */
/* Workqueue worker: runs in sleepable context                         */
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

static void lha_capture_worker(struct work_struct *work)
{
	struct lha_pending_event *pending =
		container_of(work, struct lha_pending_event, work);
	struct lha_enriched_event_v1 out;

	lha_centos9_resolve_event(&pending->ev, &out);

	lha_release_capture_refs(&pending->ev);
	kfree(pending);
	atomic_dec(&lha_pending_count);
}

/* ------------------------------------------------------------------ */
/* Helper: grab stable references in the entry handler (atomic ctx)    */
/* ------------------------------------------------------------------ */

static void lha_grab_subject_refs(struct lha_capture_data *data)
{
	data->task = current;
	get_task_struct(current);
	data->cred = get_current_cred();
}

/* ------------------------------------------------------------------ */
/* Helper: queue an event from the return handler (atomic ctx)         */
/* ------------------------------------------------------------------ */

static void lha_queue_event(struct lha_capture_data *data, int ret)
{
	struct lha_pending_event *pending;

	if (!data->refs_valid)
		return;

	if (atomic_read(&lha_pending_count) >=
	    (int)READ_ONCE(lha_capture_max_pending))
		goto drop;

	pending = kzalloc(sizeof(*pending), GFP_ATOMIC);
	if (!pending)
		goto drop;

	INIT_WORK(&pending->work, lha_capture_worker);
	pending->ev.version = 1;
	pending->ev.hook_id = data->hook_id;
	pending->ev.ts_ns = data->ts_ns;
	pending->ev.ret = ret;
	pending->ev.subject.task = data->task;
	pending->ev.subject.cred = data->cred;

	switch (data->hook_id) {
	case LHA_HOOK_INODE_PERMISSION:
		pending->ev.args.inode_permission.inode =
			data->args.inode_permission.inode;
		pending->ev.args.inode_permission.mask =
			data->args.inode_permission.mask;
		break;
	case LHA_HOOK_FILE_OPEN:
		pending->ev.args.file_open.file = data->args.file_open.file;
		break;
	case LHA_HOOK_FILE_PERMISSION:
		pending->ev.args.file_permission.file =
			data->args.file_permission.file;
		pending->ev.args.file_permission.mask =
			data->args.file_permission.mask;
		break;
	default:
		kfree(pending);
		goto drop;
	}

	/* Ownership of refs transferred to pending->ev. */
	data->refs_valid = false;
	atomic_inc(&lha_pending_count);
	schedule_work(&pending->work);
	return;

drop:
	/* Release refs that were not transferred. */
	if (data->task)
		put_task_struct(data->task);
	if (data->cred)
		put_cred(data->cred);

	switch (data->hook_id) {
	case LHA_HOOK_INODE_PERMISSION:
		if (data->args.inode_permission.inode)
			iput(data->args.inode_permission.inode);
		break;
	case LHA_HOOK_FILE_OPEN:
		if (data->args.file_open.file)
			fput(data->args.file_open.file);
		break;
	case LHA_HOOK_FILE_PERMISSION:
		if (data->args.file_permission.file)
			fput(data->args.file_permission.file);
		break;
	default:
		break;
	}
	data->refs_valid = false;
}

/* ================================================================== */
/* kretprobe: selinux_inode_permission(struct inode *inode, int mask)  */
/* ================================================================== */

static int lha_inode_perm_entry(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct lha_capture_data *data = (void *)ri->data;
	struct inode *inode = (struct inode *)LHA_ARG0(regs);
	int mask = (int)LHA_ARG1(regs);

	memset(data, 0, sizeof(*data));
	data->hook_id = LHA_HOOK_INODE_PERMISSION;
	data->ts_ns = ktime_get_real_ns();

	if (!inode)
		return 1; /* skip this instance */

	data->args.inode_permission.inode = igrab(inode);
	if (!data->args.inode_permission.inode)
		return 1;

	data->args.inode_permission.mask = mask;
	lha_grab_subject_refs(data);
	data->refs_valid = true;
	return 0;
}

static int lha_inode_perm_ret(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct lha_capture_data *data = (void *)ri->data;
	int ret = (int)regs_return_value(regs);

	lha_queue_event(data, ret);
	return 0;
}

static struct kretprobe lha_inode_perm_kretprobe = {
	.handler = lha_inode_perm_ret,
	.entry_handler = lha_inode_perm_entry,
	.data_size = sizeof(struct lha_capture_data),
	.maxactive = 64,
	.kp.symbol_name = "selinux_inode_permission",
};

/* ================================================================== */
/* kretprobe: selinux_file_open(struct file *file)                    */
/* ================================================================== */

static int lha_file_open_entry(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct lha_capture_data *data = (void *)ri->data;
	struct file *file = (struct file *)LHA_ARG0(regs);

	memset(data, 0, sizeof(*data));
	data->hook_id = LHA_HOOK_FILE_OPEN;
	data->ts_ns = ktime_get_real_ns();

	if (!file || IS_ERR(file))
		return 1;

	get_file(file);
	data->args.file_open.file = file;
	lha_grab_subject_refs(data);
	data->refs_valid = true;
	return 0;
}

static int lha_file_open_ret(struct kretprobe_instance *ri,
			     struct pt_regs *regs)
{
	struct lha_capture_data *data = (void *)ri->data;
	int ret = (int)regs_return_value(regs);

	lha_queue_event(data, ret);
	return 0;
}

static struct kretprobe lha_file_open_kretprobe = {
	.handler = lha_file_open_ret,
	.entry_handler = lha_file_open_entry,
	.data_size = sizeof(struct lha_capture_data),
	.maxactive = 64,
	.kp.symbol_name = "selinux_file_open",
};

/* ================================================================== */
/* kretprobe: selinux_file_permission(struct file *file, int mask)    */
/* ================================================================== */

static int lha_file_perm_entry(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct lha_capture_data *data = (void *)ri->data;
	struct file *file = (struct file *)LHA_ARG0(regs);
	int mask = (int)LHA_ARG1(regs);

	memset(data, 0, sizeof(*data));
	data->hook_id = LHA_HOOK_FILE_PERMISSION;
	data->ts_ns = ktime_get_real_ns();

	if (!file || IS_ERR(file))
		return 1;

	get_file(file);
	data->args.file_permission.file = file;
	data->args.file_permission.mask = mask;
	lha_grab_subject_refs(data);
	data->refs_valid = true;
	return 0;
}

static int lha_file_perm_ret(struct kretprobe_instance *ri,
			     struct pt_regs *regs)
{
	struct lha_capture_data *data = (void *)ri->data;
	int ret = (int)regs_return_value(regs);

	lha_queue_event(data, ret);
	return 0;
}

static struct kretprobe lha_file_perm_kretprobe = {
	.handler = lha_file_perm_ret,
	.entry_handler = lha_file_perm_entry,
	.data_size = sizeof(struct lha_capture_data),
	.maxactive = 64,
	.kp.symbol_name = "selinux_file_permission",
};

/* ================================================================== */
/* Module init / exit                                                  */
/* ================================================================== */

static int __init lha_centos9_capture_init(void)
{
	int rc;

	rc = register_kretprobe(&lha_inode_perm_kretprobe);
	if (rc) {
		pr_err("lha_centos9_capture: failed to register kretprobe for selinux_inode_permission: %d\n",
		       rc);
		return rc;
	}

	rc = register_kretprobe(&lha_file_open_kretprobe);
	if (rc) {
		pr_err("lha_centos9_capture: failed to register kretprobe for selinux_file_open: %d\n",
		       rc);
		goto err_unreg_inode;
	}

	rc = register_kretprobe(&lha_file_perm_kretprobe);
	if (rc) {
		pr_err("lha_centos9_capture: failed to register kretprobe for selinux_file_permission: %d\n",
		       rc);
		goto err_unreg_file_open;
	}

	pr_info("lha_centos9_capture: loaded, hooking 3 SELinux LSM functions (max_pending=%u)\n",
		lha_capture_max_pending);
	return 0;

err_unreg_file_open:
	unregister_kretprobe(&lha_file_open_kretprobe);
err_unreg_inode:
	unregister_kretprobe(&lha_inode_perm_kretprobe);
	return rc;
}

static void __exit lha_centos9_capture_exit(void)
{
	unregister_kretprobe(&lha_file_perm_kretprobe);
	unregister_kretprobe(&lha_file_open_kretprobe);
	unregister_kretprobe(&lha_inode_perm_kretprobe);

	/*
	 * After unregistering, flush the system workqueue so all pending
	 * workers finish and release their references before we unload.
	 */
	flush_scheduled_work();

	pr_info("lha_centos9_capture: unloaded (missed: inode_perm=%d file_open=%d file_perm=%d)\n",
		lha_inode_perm_kretprobe.nmissed,
		lha_file_open_kretprobe.nmissed,
		lha_file_perm_kretprobe.nmissed);
}

module_init(lha_centos9_capture_init);
module_exit(lha_centos9_capture_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lha-team");
MODULE_DESCRIPTION("CentOS Stream 9 kretprobe-based LSM hook capture module");
MODULE_SOFTDEP("pre: lha_centos9_resolver");
