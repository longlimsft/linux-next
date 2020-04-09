// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020, Microsoft Corporation.
 *
 * Authors:
 *   Long Li <longli@microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include "rimbaud.h"

static struct rimbaud_device rimbaud_dev; // the only one

static int rimbaud_ringbuffer_size = (128 * 1024);

static const struct hv_vmbus_device_id id_table[] = {
	{ HV_RIMBAUD_GUID,
	  .driver_data = 0
	},
	{ },
};

#define ERR 0
#define WAN 1
#define DBG 2
static int log_level = DBG;

#define rimbaud_log(level, fmt, args...)	\
do {	\
	if (level <= log_level)	\
		printk(KERN_ERR "%s:%d " fmt, __func__, __LINE__, ##args);	\
} while (0)

#define rimbaud_dbg(fmt, args...) rimbaud_log(DBG, fmt, ##args)
#define rimbaud_warn(fmt, args...) rimbaud_log(WAN, fmt, ##args)
#define rimbaud_err(fmt, args...) rimbaud_log(ERR, fmt, ##args)

struct xs_fastpath_vsp_request_ctx {
	struct list_head list;
	struct completion wait_vsp;
	struct xs_fastpath_request_sync *request;
};

static void rimbaud_on_channel_callback(void *context)
{
	struct vmbus_channel *channel = (struct vmbus_channel *)context;
	const struct vmpacket_descriptor *desc;

	rimbaud_dbg("entering interrupt from vmbus\n");
	foreach_vmbus_pkt(desc, channel) {
		struct xs_fastpath_vsp_request_ctx *request_ctx =
			(struct xs_fastpath_vsp_request_ctx *)((unsigned long) desc->trans_id);
		struct xs_fastpath_vsp_response *response = hv_pkt_data(desc);

		rimbaud_dbg("got response for request %pUb\n", &request_ctx->request->guid);
		request_ctx->request->response.status = response->error;
		request_ctx->request->response.response_len = response->response_len;
		complete(&request_ctx->wait_vsp);
	}

}

#if 0
static void rimbaud_on_channel_callback(void *context)
{
	struct vmbus_channel *channel = (struct vmbus_channel *)context;
	const struct vmpacket_descriptor *desc;
	struct hv_device *device = channel->device_obj;
	struct rimbaud_device *dev = hv_get_drvdata(device);

	rimbaud_dbg("entering interrupt from vmbus\n");
	foreach_vmbus_pkt(desc, channel) {
		void *packet = hv_pkt_data(desc);
		struct rimbaud_version_negotiate_response *negotiate_response;
		struct rimbaud_request *request =
			(struct rimbaud_request *)((unsigned long) desc->trans_id);

		rimbaud_dbg("got response for type %d\n", request->type);
		switch (request->type) {
		case VERSION_NEGOTIATE:
			negotiate_response = packet;
			rimbaud_dbg("negotiate response length %d status %d\n",
				negotiate_response->header.length,
				negotiate_response->header.status);
			memcpy(request->vsp_response_packet, packet, negotiate_response->header.length);
			complete(&request->wait_event);
			break;

		case OPEN_BLOB:
			memcpy(request->vsp_response_packet, packet,
				sizeof(struct rimbaud_open_blob_response));
			complete(&request->wait_event);
			break;

		case CLOSE_BLOB:
			memcpy(request->vsp_response_packet, packet,
				sizeof(struct rimbaud_packet_response));
			complete(&request->wait_event);
			break;

		case METADATA_CACHE_HINT:
			memcpy(request->vsp_response_packet, packet,
				sizeof(struct rimbaud_packet_response));
			complete(&request->wait_event);
			break;

		case GET_BLOB:
			memcpy(request->vsp_response_packet, packet,
				sizeof(struct rimbaud_get_blob_response));
			process_vsp_get_blob_response(device, request);
			break;

		default:
			rimbaud_err("unknown response from VSP type %d\n",
				request->type);
		}

		if (atomic_dec_and_test(&dev->vsp_pending))
			wake_up(&dev->wait_remove);
	}
	rimbaud_dbg("exiting interrupt from vmbus\n");
}
#endif

/*
static char *rimbaud_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "rimbaud/%s", dev_name(dev));
}
*/
static int rimbaud_fop_open(struct inode *inode, struct file *file)
{
//	struct rimbaud_device *dev =
//		container_of(inode->i_cdev, struct rimbaud_device, cdev);
//	file->private_data = dev;
	file->private_data = &rimbaud_dev;
	rimbaud_dbg("checkpoint\n");
	return 0;
}

static int rimbaud_fop_release(struct inode *inode, struct file *file)
{
//	struct rimbaud_device *dev =
//		container_of(inode->i_cdev, struct rimbaud_device, cdev);
	rimbaud_dbg("checkpoint\n");
	return 0;
}

static inline bool rimbaud_safe_file_access(struct file *file)
{
	return file->f_cred == current_cred() && !uaccess_kernel();
}

static ssize_t rimbaud_fop_write(struct file *file, const char __user * buf,
		size_t count, loff_t *pos)
{
	struct rimbaud_device *dev = file->private_data;

	rimbaud_dbg("count %ld *pos %lld\n", count, *pos);

	if (READ_ONCE(dev->removing))
		return -ENOENT;

	if (!rimbaud_safe_file_access(file)) {
		rimbaud_err("process %d(%s) changed security contexts after"
			" opening file descriptor\n",
			task_tgid_vnr(current), current->comm);
		return -EACCES;
	}
#if 0
	if (count < sizeof(hdr)) {
		rimbaud_err("got a command size %ld < hdr size\n", count);
		return -EINVAL;
	}

	rc = copy_from_user(&hdr, buf, sizeof(hdr));
	if (rc)
		return -EPERM;
	rimbaud_dbg("got command=%d\n", hdr.command);

	if (hdr.in_bytes != count - sizeof(hdr)) {
		rimbaud_err("hdr.in_bytes=%u count=%ld mismatch\n",
			hdr.in_bytes, count);
		return -EINVAL;
	}

	if (hdr.out_bytes) {
		response_addr = u64_to_user_ptr(hdr.response_addr);

		// check if we can write the response back to user
		if (!access_ok(response_addr, hdr.out_bytes)) {
			rimbaud_err("can't write response %u bytes\n",
				hdr.out_bytes);
			return -EPERM;
		}
	}

	rimbaud_dbg("calling subcommand count=%lu in_bytes=%u out_bytes=%u\n",
		count - sizeof(hdr), hdr.in_bytes, hdr.out_bytes);


	// TEST ONLY, the following code is to be removed
test_mode:
	copy_from_user(my_buf, buf, count);
	*pos += count;

	my_buf[count] = 0;
	rimbaud_dbg("got data %s\n", my_buf);

	// do something to see if it can be returned to user
	write_buf[0] = '0';
	write_buf[1] = '1';
	write_buf[2] = '2';
	write_buf[3] = '3';
#endif
	return count;
}

static int get_buffer_pages(int rw, void __user *buffer, u32 buffer_len, struct page ***pages, size_t *start, size_t *num_pages)
{
	struct iovec iov;
	struct iov_iter iter;
	size_t result;
	int ret;

	ret = import_single_range(rw, buffer, buffer_len, &iov, &iter);
	if (ret) {
		rimbaud_err("request buffer access error %d\n", ret);
		return ret;
	}

	result = iov_iter_get_pages_alloc(&iter, pages, buffer_len, start);
	if (result != buffer_len) {
		rimbaud_err("can't ping user pages requested %d got %lu\n", buffer_len, result);
		return -ENOMEM;
	}

	*num_pages = (result + *start + PAGE_SIZE - 1) / PAGE_SIZE;
	return 0;
}

static void fill_in_page_buffer(struct hv_page_buffer *page_buffer, int *index, struct page **pages, unsigned long num_pages, unsigned long start, unsigned long length)
{
	int i, page_idx = *index;
	for (i = 0; i < num_pages; i++) {
		if (i == 0) {
			/* first page */
			page_buffer[page_idx].offset = start;
			page_buffer[page_idx].len = min(PAGE_SIZE - start, length);
		} else if (i == num_pages - 1) {
			/* last page */
			page_buffer[page_idx].len = length - (PAGE_SIZE * i - start);
		} else
			page_buffer[page_idx].len = PAGE_SIZE;
		page_buffer[page_idx++].pfn = page_to_pfn(pages[i]);
	}
	*index = page_idx;
}

static void free_buffer_pages(size_t num_pages, struct page **pages)
{
	unsigned long i;
	for (i = 0; i < num_pages; i++)
		put_page(pages[i]);
	kfree(pages);
}

static long rimbaud_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct rimbaud_device *dev = filp->private_data;
//	void __user *argp = (void __user *) arg;
	char __user *argp = (char __user *) arg;
	struct xs_fastpath_request_sync request;
	struct xs_fastpath_vsp_request_ctx *request_ctx;
	unsigned long flags;
	int ret;
	size_t request_start, request_num_pages = 0, response_start, response_num_pages = 0, data_start, data_num_pages = 0, total_num_pages;
	struct page **request_pages = NULL, **response_pages = NULL, **data_pages = NULL;
	struct vmbus_channel_packet_page_buffer_array *desc;
	struct hv_page_buffer *page_buffer;
	int desc_size;
	int page_idx;
	struct xs_fastpath_vsp_request *vsp_request;

	if (!rimbaud_safe_file_access(filp)) {
		rimbaud_err("process %d(%s) changed security contexts after"
			" opening file descriptor\n",
			task_tgid_vnr(current), current->comm);
		return -EACCES;
	}

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EPERM;

	rimbaud_dbg("rimbaud ioctl request guid %pUb timeout %u request_len %u response_len %u data_len %u request_buffer %llx response_buffer %llx data_buffer %llx\n", &request.guid, request.timeout, request.request_len, request.response_len, request.data_len, request.request_buffer, request.response_buffer, request.data_buffer);

	request_ctx = kzalloc(sizeof(*request_ctx), GFP_KERNEL);
	if (!request_ctx)
		return -ENOMEM;

	init_completion(&request_ctx->wait_vsp);
	request_ctx->request = &request;

	ret = get_buffer_pages(READ, (void __user *) request.request_buffer, request.request_len, &request_pages, &request_start, &request_num_pages);
	if (ret)
		goto get_user_page_failed;

	ret = get_buffer_pages(WRITE, (void __user *) request.response_buffer, request.response_len, &response_pages, &response_start, &response_num_pages);
	if (ret)
		goto get_user_page_failed;

	if (request.data_len) {
		ret = get_buffer_pages(READ | WRITE, (void __user *) request.data_buffer, request.data_len, &data_pages, &data_start, &data_num_pages);
		if (ret)
			goto get_user_page_failed;
	}

	total_num_pages = request_num_pages + response_num_pages + data_num_pages;
	if (total_num_pages > 8192) {
		rimbaud_err("number of DMA pages %lu buffer exceeding 8k\n", total_num_pages);
		ret = -EINVAL;
		goto get_user_page_failed;
	}

	/* Construct a VMBUS packet and send it over to VSP */
	desc_size = sizeof(struct vmbus_channel_packet_page_buffer_array) + sizeof(struct hv_page_buffer) * total_num_pages;
	desc = kzalloc(desc_size, GFP_KERNEL);
	vsp_request= kzalloc(sizeof(*vsp_request), GFP_KERNEL);
	if (!desc || !vsp_request) {
		kfree(desc);
		kfree(vsp_request);
		ret = -ENOMEM;
		goto get_user_page_failed;
	}
	desc->rangecount = total_num_pages;

	page_buffer = desc->range;
	page_idx = 0;
	if (request.data_len) {
		fill_in_page_buffer(page_buffer, &page_idx, data_pages, data_num_pages, data_start, request.data_len);
		vsp_request->data_buffer_offset = data_start;
		vsp_request->data_buffer_length = request.data_len;
		vsp_request->data_buffer_valid = 1;
	}

	fill_in_page_buffer(page_buffer, &page_idx, request_pages, request_num_pages, request_start, request.request_len);
	vsp_request->request_buffer_offset = request_start + data_num_pages * PAGE_SIZE;
	vsp_request->request_buffer_length = request.request_len;

	fill_in_page_buffer(page_buffer, &page_idx, response_pages, response_num_pages, response_start, request.response_len);
	vsp_request->response_buffer_offset = response_start + (data_num_pages + request_num_pages) * PAGE_SIZE;
	vsp_request->response_buffer_length = request.response_len;

	vsp_request->version = 0;
	vsp_request->timeout_ms = request.timeout;
	vsp_request->operation_type = XS_FASTPATH_DRIVER_USER_REQUEST;
	guid_copy(&vsp_request->transaction_id, &request.guid);

	spin_lock_irqsave(&dev->vsp_pending_lock, flags);
	if (dev->removing) {
		spin_unlock_irqrestore(&dev->vsp_pending_lock, flags);
		ret = -ENODEV;
		goto get_user_page_failed;
	}
	list_add_tail(&request_ctx->list, &dev->vsp_pending_list);
	spin_unlock_irqrestore(&dev->vsp_pending_lock, flags);

	ret = vmbus_sendpacket_pagebuffer_desc(dev->device->channel, desc, desc_size, vsp_request, sizeof(*vsp_request), (u64) request_ctx);
	kfree(desc);
	kfree(vsp_request);
	if (ret)
		goto vmbus_send_failed;

	wait_for_completion(&request_ctx->wait_vsp);

	/* At this time, the response is already written to the user-buffer by VMBUS completion routine, clean up resources and return to user-mode */
	if (copy_to_user(argp +
			offsetof(struct xs_fastpath_request_sync,
				response.status),
			&request.response.status,
			sizeof(request.response.status))) {
		ret = -EPERM;
		goto vmbus_send_failed;
	}

	if (copy_to_user(argp +
			offsetof(struct xs_fastpath_request_sync,
				response.response_len),
			&request.response.response_len,
			sizeof(request.response.response_len)))
		ret = -EPERM;

vmbus_send_failed:
	spin_lock_irqsave(&dev->vsp_pending_lock, flags);
	list_del(&request_ctx->list);
	if (list_empty(&dev->vsp_pending_list))
		wake_up(&dev->wait_remove);
	spin_unlock_irqrestore(&dev->vsp_pending_lock, flags);

get_user_page_failed:
	free_buffer_pages(request_num_pages, request_pages);
	free_buffer_pages(response_num_pages, response_pages);
	free_buffer_pages(data_num_pages, data_pages);

	kfree(request_ctx);
	return ret;
}

static const struct file_operations rimbaud_client_fops = {
	.owner	= THIS_MODULE,
	.open	= rimbaud_fop_open,
	.write 	= rimbaud_fop_write,
	.unlocked_ioctl = rimbaud_ioctl,
	.release = rimbaud_fop_release,
};

#define RIMBAUD_MINOR_DEV 100
static struct miscdevice rimbaud_misc_device = {
	RIMBAUD_MINOR_DEV,
	"azure_blob",
        &rimbaud_client_fops,
};


static void rimbaud_remove_device(struct rimbaud_device *dev)
{
	unsigned long flags;
	spin_lock_irqsave(&dev->vsp_pending_lock, flags);
	dev->removing = true;
	spin_unlock_irqrestore(&dev->vsp_pending_lock, flags);

	misc_deregister(&rimbaud_misc_device);
#if 0
	device_destroy(dev->class, dev->devno);
	cdev_del(&dev->cdev);
	class_destroy(dev->class);
	unregister_chrdev_region(dev->devno, 1);
#endif

	// at this point, we won't get any requests from user-mode
}

static int rimbaud_create_device(struct rimbaud_device *dev)
{
//	struct device *char_dev;
//	dev_t devno;
	int rc;

	rc = misc_register(&rimbaud_misc_device);
	if (rc)
		rimbaud_err("misc_register failed rc %d\n", rc);

	return rc;

#if 0
	rc = alloc_chrdev_region(&devno, 0, 1, "rimbaud");
	if (unlikely(rc)) {
		rimbaud_err("alloc_chrdev_region rc=%d\n", rc);
		return rc;
	}
	dev->devno = devno;
	rimbaud_dbg("devno=%d\n", devno);

	dev->class = class_create(THIS_MODULE, "rimbaud");
	if (IS_ERR(dev->class)) {
		rc = PTR_ERR(dev->class);
		rimbaud_err("class_create failed rc %d\n", rc);
		goto class_create_fail;
	}
	dev->class->devnode = rimbaud_devnode;

	// add device
	cdev_init(&dev->cdev, &rimbaud_client_fops);
	rc = cdev_add(&dev->cdev, devno, 1);
	if (rc) {
		rimbaud_err("cdev_add failed rc %d\n", rc);
		goto cdev_add_fail;
	}

	char_dev = device_create(dev->class, NULL, devno, NULL, "rimbaud");
	if (IS_ERR(char_dev)) {
		rc = PTR_ERR(char_dev);
		rimbaud_err("device_create failed rc %d\n", rc);
		goto device_create_fail;
	}
	dev->chardev = char_dev;

	return 0;

device_create_fail:
	cdev_del(&dev->cdev);

cdev_add_fail:
	class_destroy(dev->class);

class_create_fail:
	unregister_chrdev_region(devno, 1);

	return rc;
#endif
}

static int rimbaud_connect_to_vsp(struct hv_device *device, u32 ring_size)
{
	int ret;

	init_waitqueue_head(&rimbaud_dev.wait_remove);
	rimbaud_dev.removing = false;

	rimbaud_dev.device = device;

	ret = vmbus_open(device->channel, ring_size, ring_size, NULL, 0,
			rimbaud_on_channel_callback, device->channel);

	rimbaud_dbg("ret %d\n", ret);
	if (ret)
		return ret;

	hv_set_drvdata(device, &rimbaud_dev);

	return ret;
}

static void rimbaud_remove_vmbus(struct hv_device *device)
{
	struct rimbaud_device *dev = hv_get_drvdata(device);
	unsigned long flags;

	spin_lock_irqsave(&dev->vsp_pending_lock, flags);
	if (!list_empty(&dev->vsp_pending_list)) {
		spin_unlock_irqrestore(&dev->vsp_pending_lock, flags);
		wait_event(dev->wait_remove, list_empty(&dev->vsp_pending_list));
	} else
		spin_unlock_irqrestore(&dev->vsp_pending_lock, flags);

	// at this point, no VSC/VSP traffic is possible over vmbus
	hv_set_drvdata(device, NULL);
	vmbus_close(device->channel);
}

static int rimbaud_probe(struct hv_device *device,
			const struct hv_vmbus_device_id *dev_id)
{
	int rc;

	rimbaud_dbg("probing device\n");

	rc = rimbaud_connect_to_vsp(device, rimbaud_ringbuffer_size);
	if (rc) {
		rimbaud_err("error connecting to VSP rc %d\n", rc);
		return rc;
	}

	// create user-mode client library facing device
	rc = rimbaud_create_device(&rimbaud_dev);
	if (rc) {
		rimbaud_remove_vmbus(device);
		return rc;
	}

	rimbaud_dbg("successfully probed device\n");
	return 0;
}

static int rimbaud_remove(struct hv_device *dev)
{
	struct rimbaud_device *device = hv_get_drvdata(dev);

	rimbaud_remove_device(device);
	rimbaud_remove_vmbus(dev);
	return 0;
}

static struct hv_driver rimbaud_drv = {
	.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = rimbaud_probe,
	.remove = rimbaud_remove,
	.driver = {
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

static int __init rimbaud_drv_init(void)
{
	return vmbus_driver_register(&rimbaud_drv);
}

static void __exit rimbaud_drv_exit(void)
{
	vmbus_driver_unregister(&rimbaud_drv);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Microsoft Azure Rimbaud storage driver");
module_init(rimbaud_drv_init);
module_exit(rimbaud_drv_exit);
