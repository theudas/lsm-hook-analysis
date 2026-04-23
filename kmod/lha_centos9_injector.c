#include "lha_centos9_resolver.h"

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>

#define LHA_DEBUGFS_DIR "lha_centos9"
#define LHA_LAST_JSON_LEN 8192

static struct dentry *lha_debugfs_dir;
static char lha_last_json[LHA_LAST_JSON_LEN];
static DEFINE_MUTEX(lha_last_json_lock);

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

static void lha_release_capture_refs(struct lha_capture_event_v1 *event)
{
	if (!event)
		return;

	switch (event->hook_id) {
	case LHA_HOOK_INODE_PERMISSION:
		if (event->args.inode_permission.inode)
			iput(event->args.inode_permission.inode);
		break;
	case LHA_HOOK_FILE_OPEN:
		if (event->args.file_open.file)
			fput(event->args.file_open.file);
		break;
	case LHA_HOOK_FILE_PERMISSION:
		if (event->args.file_permission.file)
			fput(event->args.file_permission.file);
		break;
	default:
		break;
	}

	if (event->subject.task)
		put_task_struct(event->subject.task);
	if (event->subject.cred)
		put_cred(event->subject.cred);
}

static void lha_capture_subject_refs(struct lha_capture_event_v1 *event)
{
	event->subject.task = current;
	get_task_struct(current);
	event->subject.cred = get_current_cred();
}

static void lha_store_last_json(const char *json)
{
	mutex_lock(&lha_last_json_lock);
	lha_copy_string(lha_last_json, sizeof(lha_last_json), json);
	mutex_unlock(&lha_last_json_lock);
}

static int lha_run_injected_event(struct lha_capture_event_v1 *event)
{
	struct lha_enriched_event_v1 *out;
	char *json;
	int rc;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	json = kmalloc(LHA_LAST_JSON_LEN, GFP_KERNEL);
	if (!json) {
		kfree(out);
		return -ENOMEM;
	}

	rc = lha_centos9_resolve_event(event, out);
	if (rc)
		goto out_free;

	rc = lha_centos9_format_json(out, json, LHA_LAST_JSON_LEN);
	if (rc)
		goto out_free;

	lha_store_last_json(json);
	pr_info("lha_centos9_injector: generated %s event\n", out->hook);

out_free:
	kfree(json);
	kfree(out);
	return rc;
}

static int lha_inject_sample_inode_permission(void)
{
	struct lha_capture_event_v1 event;
	struct path path;
	struct inode *inode;
	int rc;

	memset(&event, 0, sizeof(event));
	rc = kern_path("/tmp", LOOKUP_FOLLOW, &path);
	if (rc)
		return rc;

	inode = igrab(d_inode(path.dentry));
	path_put(&path);
	if (!inode)
		return -ENOENT;

	event.version = 1;
	event.hook_id = LHA_HOOK_INODE_PERMISSION;
	event.ts_ns = ktime_get_real_ns();
	event.ret = 0;
	lha_capture_subject_refs(&event);
	event.args.inode_permission.inode = inode;
	event.args.inode_permission.mask = LHA_MAY_EXEC;

	rc = lha_run_injected_event(&event);
	lha_release_capture_refs(&event);
	return rc;
}

static int lha_inject_sample_file_open(void)
{
	struct lha_capture_event_v1 event;
	struct file *file;
	int rc;

	memset(&event, 0, sizeof(event));
	file = filp_open("/etc/hosts", O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);

	event.version = 1;
	event.hook_id = LHA_HOOK_FILE_OPEN;
	event.ts_ns = ktime_get_real_ns();
	event.ret = 0;
	lha_capture_subject_refs(&event);
	event.args.file_open.file = file;

	rc = lha_run_injected_event(&event);
	lha_release_capture_refs(&event);
	return rc;
}

static int lha_inject_sample_file_permission(void)
{
	struct lha_capture_event_v1 event;
	struct file *file;
	int rc;

	memset(&event, 0, sizeof(event));
	file = filp_open("/tmp/lha_inject.log", O_CREAT | O_WRONLY | O_APPEND, 0600);
	if (IS_ERR(file))
		return PTR_ERR(file);

	event.version = 1;
	event.hook_id = LHA_HOOK_FILE_PERMISSION;
	event.ts_ns = ktime_get_real_ns();
	event.ret = -EACCES;
	lha_capture_subject_refs(&event);
	event.args.file_permission.file = file;
	event.args.file_permission.mask = LHA_MAY_WRITE;

	rc = lha_run_injected_event(&event);
	lha_release_capture_refs(&event);
	return rc;
}

static ssize_t lha_last_json_read(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	ssize_t rc;

	(void)file;

	mutex_lock(&lha_last_json_lock);
	rc = simple_read_from_buffer(user_buf, count, ppos,
				     lha_last_json,
				     strnlen(lha_last_json, sizeof(lha_last_json)));
	mutex_unlock(&lha_last_json_lock);
	return rc;
}

static ssize_t lha_inject_write(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	char *cmd;
	size_t len;
	int rc;

	(void)file;
	(void)ppos;

	if (count == 0)
		return 0;

	len = min_t(size_t, count, 63);
	cmd = kzalloc(len + 1, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	if (copy_from_user(cmd, user_buf, len)) {
		kfree(cmd);
		return -EFAULT;
	}

	strim(cmd);
	if (sysfs_streq(cmd, "sample_inode")) {
		rc = lha_inject_sample_inode_permission();
	} else if (sysfs_streq(cmd, "sample_open")) {
		rc = lha_inject_sample_file_open();
	} else if (sysfs_streq(cmd, "sample_append")) {
		rc = lha_inject_sample_file_permission();
	} else {
		kfree(cmd);
		return -EINVAL;
	}

	kfree(cmd);
	if (rc)
		return rc;

	return (ssize_t)count;
}

static const struct file_operations lha_last_json_fops = {
	.owner = THIS_MODULE,
	.read = lha_last_json_read,
	.llseek = default_llseek,
};

static const struct file_operations lha_inject_fops = {
	.owner = THIS_MODULE,
	.write = lha_inject_write,
	.llseek = no_llseek,
};

static int __init lha_centos9_injector_init(void)
{
	lha_copy_string(lha_last_json, sizeof(lha_last_json),
			"{\"status\":\"no event injected yet\"}\n");
	lha_debugfs_dir = debugfs_create_dir(LHA_DEBUGFS_DIR, NULL);
	if (IS_ERR_OR_NULL(lha_debugfs_dir)) {
		pr_err("lha_centos9_injector: failed to create debugfs dir\n");
		return lha_debugfs_dir ? PTR_ERR(lha_debugfs_dir) : -ENOMEM;
	}

	if (!debugfs_create_file("inject", 0200, lha_debugfs_dir, NULL,
				 &lha_inject_fops) ||
	    !debugfs_create_file("last_json", 0400, lha_debugfs_dir, NULL,
				 &lha_last_json_fops)) {
		debugfs_remove_recursive(lha_debugfs_dir);
		lha_debugfs_dir = NULL;
		pr_err("lha_centos9_injector: failed to create debugfs files\n");
		return -ENOMEM;
	}

	pr_info("lha_centos9_injector loaded\n");
	return 0;
}

static void __exit lha_centos9_injector_exit(void)
{
	debugfs_remove_recursive(lha_debugfs_dir);
	pr_info("lha_centos9_injector unloaded\n");
}

module_init(lha_centos9_injector_init);
module_exit(lha_centos9_injector_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI Codex");
MODULE_DESCRIPTION("CentOS Stream 9 self-test injector for the resolver API");
MODULE_SOFTDEP("pre: lha_centos9_resolver");
