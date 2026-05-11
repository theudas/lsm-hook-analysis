#include "lha_centos9_event_channel.h"

#include <linux/atomic.h>
#include <linux/build_bug.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#define LHA_DEFAULT_QUEUE_CAPACITY 1024U

struct lha_event_channel_state {
	spinlock_t lock;
	struct mutex read_lock;
	wait_queue_head_t readq;
	struct miscdevice miscdev;
	struct lha_event_frame_v1 *queue;
	u32 queue_capacity;
	u32 head;
	u32 tail;
	u32 count;
	bool ready;
	bool stopping;
	atomic_t reader_attached;
	atomic64_t next_seq;
	atomic64_t submitted_total;
	atomic64_t dropped_total;
	atomic64_t last_drop_ns;
};

static unsigned int lha_event_queue_capacity = LHA_DEFAULT_QUEUE_CAPACITY;
module_param_named(queue_capacity, lha_event_queue_capacity, uint, 0644);
MODULE_PARM_DESC(queue_capacity,
		 "Maximum number of event frames buffered in the kernel");

static struct lha_event_channel_state lha_event_channel = {
	.miscdev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = LHA_EVENT_STREAM_DEVICE_NAME,
	},
};

static const struct lha_event_channel_ops lha_event_channel_ops = {
	.owner = THIS_MODULE,
	.submit = lha_centos9_submit_event,
};

static void lha_check_payload_layout(void)
{
	BUILD_BUG_ON(sizeof(struct lha_subject_v1) !=
		     sizeof(struct lha_event_subject_v1));
	BUILD_BUG_ON(sizeof(struct lha_request_v1) !=
		     sizeof(struct lha_event_request_v1));
	BUILD_BUG_ON(sizeof(struct lha_target_v1) !=
		     sizeof(struct lha_event_target_v1));
	BUILD_BUG_ON(sizeof(struct lha_result_v1) !=
		     sizeof(struct lha_event_result_v1));
	BUILD_BUG_ON(sizeof(struct lha_enriched_event_v1) !=
		     sizeof(struct lha_event_payload_v1));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, version) !=
		     offsetof(struct lha_event_payload_v1, version));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, hook_id) !=
		     offsetof(struct lha_event_payload_v1, hook_id));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, timestamp_ns) !=
		     offsetof(struct lha_event_payload_v1, timestamp_ns));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, hook) !=
		     offsetof(struct lha_event_payload_v1, hook));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, hook_signature) !=
		     offsetof(struct lha_event_payload_v1, hook_signature));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, subject) !=
		     offsetof(struct lha_event_payload_v1, subject));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, request) !=
		     offsetof(struct lha_event_payload_v1, request));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, target) !=
		     offsetof(struct lha_event_payload_v1, target));
	BUILD_BUG_ON(offsetof(struct lha_enriched_event_v1, result) !=
		     offsetof(struct lha_event_payload_v1, result));
}

static void lha_fill_frame(struct lha_event_frame_v1 *frame,
			   const struct lha_enriched_event_v1 *event,
			   u64 seq)
{
	memset(frame, 0, sizeof(*frame));
	frame->hdr.magic = LHA_EVENT_STREAM_MAGIC;
	frame->hdr.abi_version = LHA_EVENT_STREAM_ABI_V1;
	frame->hdr.frame_type = LHA_EVENT_FRAME_DATA;
	frame->hdr.header_len = sizeof(frame->hdr);
	frame->hdr.payload_version = LHA_EVENT_STREAM_PAYLOAD_V1;
	frame->hdr.payload_len = sizeof(frame->payload);
	frame->hdr.seq = seq;
	frame->hdr.emitted_ns = ktime_get_real_ns();
	memcpy(&frame->payload, event, sizeof(frame->payload));
}

int lha_centos9_submit_event(const struct lha_enriched_event_v1 *event)
{
	struct lha_event_channel_state *sink = &lha_event_channel;
	struct lha_event_frame_v1 frame;
	unsigned long flags;
	u64 seq;

	if (!event || event->version != LHA_EVENT_STREAM_PAYLOAD_V1)
		return -EINVAL;

	if (!READ_ONCE(sink->ready) || READ_ONCE(sink->stopping))
		return -ENODEV;

	seq = (u64)atomic64_inc_return(&sink->next_seq);
	lha_fill_frame(&frame, event, seq);

	spin_lock_irqsave(&sink->lock, flags);
	if (sink->count == sink->queue_capacity) {
		atomic64_inc(&sink->dropped_total);
		atomic64_set(&sink->last_drop_ns, frame.hdr.emitted_ns);
		spin_unlock_irqrestore(&sink->lock, flags);
		return -ENOSPC;
	}

	sink->queue[sink->head] = frame;
	sink->head = (sink->head + 1) % sink->queue_capacity;
	++sink->count;
	atomic64_inc(&sink->submitted_total);
	spin_unlock_irqrestore(&sink->lock, flags);

	wake_up_interruptible(&sink->readq);
	return 0;
}
EXPORT_SYMBOL_GPL(lha_centos9_submit_event);

static int lha_event_stream_open(struct inode *inode, struct file *file)
{
	struct lha_event_channel_state *sink = &lha_event_channel;

	if (!READ_ONCE(sink->ready) || READ_ONCE(sink->stopping))
		return -ENODEV;

	if (atomic_cmpxchg(&sink->reader_attached, 0, 1) != 0)
		return -EBUSY;

	file->private_data = sink;
	return 0;
}

static int lha_event_stream_release(struct inode *inode, struct file *file)
{
	struct lha_event_channel_state *sink = file->private_data;

	if (sink)
		atomic_set(&sink->reader_attached, 0);

	return 0;
}

static ssize_t lha_event_stream_read(struct file *file, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct lha_event_channel_state *sink = file->private_data;
	struct lha_event_frame_v1 *frames;
	size_t frame_size = sizeof(struct lha_event_frame_v1);
	size_t records_requested;
	size_t records_to_copy;
	size_t bytes_to_copy;
	unsigned long flags;
	ssize_t ret;
	size_t i;

	if (!sink)
		return -ENODEV;

	if (count < frame_size || count % frame_size != 0)
		return -EINVAL;

	records_requested = count / frame_size;
	if (records_requested > sink->queue_capacity)
		records_requested = sink->queue_capacity;
	if (records_requested == 0)
		return -EINVAL;

	frames = kcalloc(records_requested, frame_size, GFP_KERNEL);
	if (!frames)
		return -ENOMEM;

	if (mutex_lock_interruptible(&sink->read_lock)) {
		kfree(frames);
		return -ERESTARTSYS;
	}

	for (;;) {
		spin_lock_irqsave(&sink->lock, flags);
		if (sink->count != 0)
			break;
		spin_unlock_irqrestore(&sink->lock, flags);

		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out_unlock;
		}

		ret = wait_event_interruptible(sink->readq,
					       READ_ONCE(sink->count) != 0 ||
					       READ_ONCE(sink->stopping));
		if (ret)
			goto out_unlock;
		if (READ_ONCE(sink->stopping) && READ_ONCE(sink->count) == 0) {
			ret = -ENODEV;
			goto out_unlock;
		}
	}

	records_to_copy = min_t(size_t, sink->count, records_requested);
	for (i = 0; i < records_to_copy; ++i) {
		frames[i] = sink->queue[sink->tail];
		sink->tail = (sink->tail + 1) % sink->queue_capacity;
		--sink->count;
	}
	spin_unlock_irqrestore(&sink->lock, flags);

	bytes_to_copy = records_to_copy * frame_size;
	if (copy_to_user(buf, frames, bytes_to_copy)) {
		ret = -EFAULT;
		goto out_unlock;
	}

	ret = (ssize_t)bytes_to_copy;

out_unlock:
	mutex_unlock(&sink->read_lock);
	kfree(frames);
	return ret;
}

static __poll_t lha_event_stream_poll(struct file *file, poll_table *wait)
{
	struct lha_event_channel_state *sink = file->private_data;
	__poll_t mask = 0;

	if (!sink)
		return EPOLLERR;

	poll_wait(file, &sink->readq, wait);

	if (READ_ONCE(sink->count) != 0)
		mask |= EPOLLIN | EPOLLRDNORM;
	if (READ_ONCE(sink->stopping))
		mask |= EPOLLERR | EPOLLHUP;

	return mask;
}

static ssize_t lha_event_stream_write(struct file *file,
				      const char __user *buf,
				      size_t count,
				      loff_t *ppos)
{
	return -EOPNOTSUPP;
}

static long lha_event_stream_ioctl(struct file *file,
				   unsigned int cmd,
				   unsigned long arg)
{
	return -EOPNOTSUPP;
}

static const struct file_operations lha_event_stream_fops = {
	.owner = THIS_MODULE,
	.open = lha_event_stream_open,
	.release = lha_event_stream_release,
	.read = lha_event_stream_read,
	.write = lha_event_stream_write,
	.poll = lha_event_stream_poll,
	.unlocked_ioctl = lha_event_stream_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = lha_event_stream_ioctl,
#endif
	.llseek = no_llseek,
};

static ssize_t abi_version_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", LHA_EVENT_STREAM_ABI_V1);
}

static ssize_t record_size_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%zu\n",
			 sizeof(struct lha_event_frame_v1));
}

static ssize_t queue_capacity_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", lha_event_channel.queue_capacity);
}

static ssize_t queue_depth_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	unsigned long flags;
	u32 count;

	spin_lock_irqsave(&lha_event_channel.lock, flags);
	count = lha_event_channel.count;
	spin_unlock_irqrestore(&lha_event_channel.lock, flags);

	return scnprintf(buf, PAGE_SIZE, "%u\n", count);
}

static ssize_t submitted_total_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(&lha_event_channel.submitted_total));
}

static ssize_t dropped_total_show(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(&lha_event_channel.dropped_total));
}

static ssize_t reader_attached_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&lha_event_channel.reader_attached));
}

static ssize_t last_drop_ns_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(&lha_event_channel.last_drop_ns));
}

static DEVICE_ATTR_RO(abi_version);
static DEVICE_ATTR_RO(record_size);
static DEVICE_ATTR_RO(queue_capacity);
static DEVICE_ATTR_RO(queue_depth);
static DEVICE_ATTR_RO(submitted_total);
static DEVICE_ATTR_RO(dropped_total);
static DEVICE_ATTR_RO(reader_attached);
static DEVICE_ATTR_RO(last_drop_ns);

static struct device_attribute *lha_event_stream_attrs[] = {
	&dev_attr_abi_version,
	&dev_attr_record_size,
	&dev_attr_queue_capacity,
	&dev_attr_queue_depth,
	&dev_attr_submitted_total,
	&dev_attr_dropped_total,
	&dev_attr_reader_attached,
	&dev_attr_last_drop_ns,
};

static int lha_event_stream_create_attrs(struct device *dev)
{
	size_t i;
	int rc;

	for (i = 0; i < ARRAY_SIZE(lha_event_stream_attrs); ++i) {
		rc = device_create_file(dev, lha_event_stream_attrs[i]);
		if (rc)
			goto err_remove;
	}

	return 0;

err_remove:
	while (i-- > 0)
		device_remove_file(dev, lha_event_stream_attrs[i]);

	return rc;
}

static void lha_event_stream_remove_attrs(struct device *dev)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lha_event_stream_attrs); ++i)
		device_remove_file(dev, lha_event_stream_attrs[i]);
}

static int __init lha_centos9_event_channel_init(void)
{
	struct lha_event_channel_state *sink = &lha_event_channel;
	int rc;

	lha_check_payload_layout();

	if (lha_event_queue_capacity == 0)
		lha_event_queue_capacity = LHA_DEFAULT_QUEUE_CAPACITY;

	spin_lock_init(&sink->lock);
	mutex_init(&sink->read_lock);
	init_waitqueue_head(&sink->readq);
	atomic_set(&sink->reader_attached, 0);
	atomic64_set(&sink->next_seq, 0);
	atomic64_set(&sink->submitted_total, 0);
	atomic64_set(&sink->dropped_total, 0);
	atomic64_set(&sink->last_drop_ns, 0);
	sink->head = 0;
	sink->tail = 0;
	sink->count = 0;
	sink->stopping = false;
	sink->ready = false;
	sink->queue_capacity = lha_event_queue_capacity;
	sink->miscdev.fops = &lha_event_stream_fops;

	sink->queue = kcalloc(sink->queue_capacity,
			      sizeof(struct lha_event_frame_v1),
			      GFP_KERNEL);
	if (!sink->queue)
		return -ENOMEM;

	rc = misc_register(&sink->miscdev);
	if (rc) {
		kfree(sink->queue);
		sink->queue = NULL;
		return rc;
	}

	rc = lha_event_stream_create_attrs(sink->miscdev.this_device);
	if (rc) {
		misc_deregister(&sink->miscdev);
		kfree(sink->queue);
		sink->queue = NULL;
		return rc;
	}

	rc = lha_centos9_register_event_channel(&lha_event_channel_ops);
	if (rc) {
		lha_event_stream_remove_attrs(sink->miscdev.this_device);
		misc_deregister(&sink->miscdev);
		kfree(sink->queue);
		sink->queue = NULL;
		return rc;
	}

	sink->ready = true;
	pr_info("lha_centos9_event_channel loaded with queue_capacity=%u\n",
		sink->queue_capacity);
	return 0;
}

static void __exit lha_centos9_event_channel_exit(void)
{
	struct lha_event_channel_state *sink = &lha_event_channel;

	sink->stopping = true;
	sink->ready = false;
	wake_up_interruptible(&sink->readq);

	lha_centos9_unregister_event_channel(&lha_event_channel_ops);
	if (sink->miscdev.this_device)
		lha_event_stream_remove_attrs(sink->miscdev.this_device);
	misc_deregister(&sink->miscdev);

	kfree(sink->queue);
	sink->queue = NULL;
	sink->queue_capacity = 0;
	sink->head = 0;
	sink->tail = 0;
	sink->count = 0;

	pr_info("lha_centos9_event_channel unloaded\n");
}

module_init(lha_centos9_event_channel_init);
module_exit(lha_centos9_event_channel_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI Codex");
MODULE_DESCRIPTION("CentOS Stream 9 event channel for continuous enriched events");
