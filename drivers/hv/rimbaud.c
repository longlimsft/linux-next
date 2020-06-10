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
static u32 negotiated_version_major;
static u32 negotiated_version_minor;

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

/*
 * blob_add_vsp_ref(), blob_remove_vsp_ref()
 * Keep track of VSP request pending acitivies on the blob handle. To maximize
 * parallelism, the blob is not locked while doing VSP request. Those functions
 * are used to prevent sending more VSP requests on this blob after CLOSE_BLOB
 * on this blob is sent to VSP.
 */
static void blob_add_vsp_ref(struct blob_handle_hash_list *hlist)
{
	hlist->vsp_request_pending++;
}

static void blob_remove_vsp_ref(struct blob_handle_hash_list *hlist)
{
	hlist->vsp_request_pending--;
	if (!hlist->vsp_request_pending)
		wake_up(&hlist->wait_close);
}

static void process_vsp_get_blob_response(
	struct hv_device *device, struct rimbaud_request *request)
{
	struct rimbaud_device *dev = hv_get_drvdata(device);
	struct blob_handle_hash_list *hlist;
	bool found = false;
	unsigned long flags;

	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	// find this handle in the hash table
	hash_for_each_possible(
		dev->read_blob_hash, hlist, node, request->handle) {
		if (hlist->blob_handle == request->handle) {
			found = true;
			break;
		}
	}
	
	if (found) {
		list_add_tail(&request->list, &hlist->head);
		rimbaud_dbg("found blob handle %d for response UUID %pUl\n",
			request->handle, &request->transaction_id);
		virt_wmb();
		wake_up(&hlist->wait_response);
	}
	else {
		/*
		 * it's impossible to get into this situaiton, if this happens
		 * it means there is a bug in VSC/VSP tracking blob handles
		 */
		WARN(1, "can't find blob handle %d\n", request->handle);
	}

	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);
}


static void rimbaud_on_channel_callback(void *context)
{
	struct vmbus_channel *channel = (struct vmbus_channel *)context;
	const struct vmpacket_descriptor *desc;
	struct hv_device *device = channel->device_obj;
	struct rimbaud_device *dev = hv_get_drvdata(device);

	rimbaud_dbg("interrupt from vmbus\n");
	foreach_vmbus_pkt(desc, channel) {
		void *packet = hv_pkt_data(desc);
		struct rimbaud_request *request =
			(struct rimbaud_request *)((unsigned long) desc->trans_id);

		rimbaud_dbg("got response for type %d\n", request->type);
		switch (request->type) {
		case VERSION_NEGOTIATE:
			memcpy(request->vsp_response_packet, packet,
				sizeof(struct rimbaud_version_negotiate_request));
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
}
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

static int process_client_get_blob_query(
	const char __user *buf, size_t count,
	u16 out_bytes, void __user * response_addr,
	struct rimbaud_device *dev)
{
	struct rimbaud_client_getblob_query queryblob;
	unsigned long flags;
	struct blob_handle_hash_list *hlist;
	bool found = false;
	struct rimbaud_request *request, *n;
	struct rimbaud_get_blob_response *vsp_response;
	int num_returned = 0;
	struct rimbaud_client_getblob_responses *response;
	struct rimbaud_client_getblob_response *cur_response;
	int user_response_size, i;
	int rc;

	if (count < sizeof(queryblob))
		return -EINVAL;

	rc = copy_from_user(&queryblob, buf, sizeof(queryblob));
	if (rc)
		return -EPERM;

	// validate response buffer size
	user_response_size = sizeof(struct rimbaud_client_getblob_responses) +
				sizeof(struct rimbaud_client_getblob_response) *
				queryblob.num_responses;
	if (out_bytes != user_response_size) {
		rimbaud_err("out_bytes %u user_response_size %d mismatch\n",
			out_bytes, user_response_size);
		return -EINVAL;
	}

	// allocate the response in kernel to be copied to user mode
	response = kmalloc(user_response_size, GFP_KERNEL);
	if (!response)
		return -ENOMEM;

	cur_response = &response->responses[0];

	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
again:
	// find this handle in the hash table
	hash_for_each_possible(
		dev->read_blob_hash, hlist, node, queryblob.blob_handle) {
		if (hlist->blob_handle == queryblob.blob_handle) {
			if (!hlist->closing) {
				found = true;
				hlist->query_pending++;
			}
			break;
		}
	}

	if (!found) {
		rimbaud_err("blob handle %d not found or it's closing\n",
			queryblob.blob_handle);
		spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);
		kfree(response);
		return -EINVAL;
	}

	if (list_empty(&hlist->head)) {
		spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

		//place on wait queue and try agin
		wait_event(hlist->wait_response,
			READ_ONCE(hlist->closing) || !list_empty(&hlist->head));

		spin_lock_irqsave(&dev->read_blob_hash_lock, flags);

		hlist->query_pending--;
		if (!hlist->query_pending)
			wake_up(&hlist->wait_close);

		goto again;
	}

	// we can return at least one response
	list_for_each_entry_safe(request, n, &hlist->head, list) {
		if (num_returned < queryblob.num_responses) {
			vsp_response = request->vsp_response_packet;

			cur_response->transaction_id = request->transaction_id;
			cur_response->bytes_written = vsp_response->bytes_written;
			cur_response->status = vsp_response->header.status;
			cur_response->blob_offset = vsp_response->blob_offset;

			cur_response++;
			num_returned++;

			rimbaud_dbg("returned response %pUl num_returned %d\n",
				&request->transaction_id, num_returned);

			list_del(&request->list);

			for (i = 0; i < request->num_pages; i++)
				put_page(request->pagevec[i]);
			kfree(request->pagevec);
			kfree(vsp_response);
			kfree(request);
		}
	}

	hlist->query_pending--;
	if (!hlist->query_pending)
		wake_up(&hlist->wait_close);
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	// copy the results to user
	rimbaud_dbg("returning %d responses to user-mode\n", num_returned);
	response->returned_responses = num_returned;

	rc = copy_to_user(response_addr, response,
		sizeof(struct rimbaud_client_getblob_responses) +
		sizeof(struct rimbaud_client_getblob_response) * num_returned);
	if (rc)
		rc = -EPERM;

	kfree(response);

	return rc;

}

static int process_client_get_blob(
	const char __user *buf, size_t count,
	struct rimbaud_device *dev)
{
	struct rimbaud_client_getblob_request readblob;
	struct rimbaud_request *request = NULL;
	struct rimbaud_get_blob_request *get_blob_vsp = NULL;
	u32 token_len;
	int rc;
	struct iovec iov;
	struct iov_iter iter;
	struct page **pagevec;
	size_t result, start;
	int i, num_pages, payload_sz;
	struct vmbus_packet_mpb_array *payload = NULL;
	bool found = false;
	unsigned long flags;
	struct blob_handle_hash_list *hlist;
	void __user * user_buffer;

	if (count < sizeof(readblob))
		return -EINVAL;

	rc = copy_from_user(&readblob, buf, sizeof(readblob));
	if (rc)
		return -EPERM;

	token_len = readblob.session_token_length;

	// validate token in the buffer
	if (readblob.session_token_offset + token_len > count) {
		rimbaud_err("token offset %d len %d exceeded packet buffer\n",
			readblob.session_token_offset, token_len);
		return -EINVAL;
	}

	// make sure we have this blob handle opened
	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	hash_for_each_possible(
		dev->read_blob_hash, hlist, node, readblob.blob_handle) {
		if (hlist->blob_handle == readblob.blob_handle) {
			if (!hlist->closing) {
				found = true;
				blob_add_vsp_ref(hlist);
			}
			break;
		}
	}
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	if (!found) {
		rimbaud_err("blob handle %d not found or being closed\n",
			readblob.blob_handle);
		return -EINVAL;
	}

	/*
	 * pin the user pages from readblob.user_buffer
	 * import_single_range() checks for access permissions
	 */
	user_buffer = (void __user *) readblob.user_buffer;
	rc = import_single_range(
		WRITE, user_buffer, readblob.user_buffer_len, &iov, &iter);
	if (rc) {
		rimbaud_err("user buffer access error %d\n", rc);
		return rc;
	}

	result = iov_iter_get_pages_alloc(
			&iter, &pagevec, readblob.user_buffer_len, &start);
	if (result != readblob.user_buffer_len) {
		rimbaud_err("can't ping user pages requested %d got %lu\n",
			readblob.user_buffer_len, result);
		return -ENOMEM;
	}

	num_pages = (result + start + PAGE_SIZE - 1) / PAGE_SIZE;
	payload_sz = num_pages * sizeof(u64) +
			sizeof(struct vmbus_packet_mpb_array);
	payload = kzalloc(payload_sz, GFP_KERNEL);
	if (!payload) {
		rc = -ENOMEM;
		goto alloc_failure;
	}

	// fill in GPA direct page array for user data
	rimbaud_dbg("allocated payload with %d pages offset %lu "
		"total size %lu trans_id %pUl\n",
		num_pages, start, result, &readblob.transaction_id);
	payload->range.len = result;
	payload->range.offset = start;
	for (i = 0; i < num_pages; i++) {
		payload->range.pfn_array[i] = page_to_pfn(pagevec[i]);
		rimbaud_dbg("page pfn index %d address %llu\n",
			i, payload->range.pfn_array[i]);
	}

	// prepare request message to VSP
	get_blob_vsp = kmalloc(sizeof(*get_blob_vsp) + token_len, GFP_KERNEL);
	if (!get_blob_vsp) {
		rc = -ENOMEM;
		goto alloc_failure;
	}

	get_blob_vsp->header.length = sizeof(*get_blob_vsp);
	get_blob_vsp->header.blob_handle = readblob.blob_handle;
	get_blob_vsp->header.type = GET_BLOB;
	get_blob_vsp->header.timeout = readblob.timeout;
	get_blob_vsp->header.transaction_id = readblob.transaction_id;

	// token starts at the end of packet header
	get_blob_vsp->header.session_token_offset = sizeof(*get_blob_vsp);
	get_blob_vsp->header.session_token_length = token_len;
	rc = copy_from_user(
		(char *) get_blob_vsp +
			get_blob_vsp->header.session_token_offset,
		buf + readblob.session_token_offset,
		token_len);
	if (rc) {
		rc = -EPERM;
		goto alloc_failure;
	}

	get_blob_vsp->guest_compress = readblob.guest_compress;
	get_blob_vsp->guest_encrypt = readblob.guest_encrypt;
	get_blob_vsp->offset = readblob.offset;
	get_blob_vsp->length = sizeof(*get_blob_vsp) + token_len;

	// prepare the request context for tracking
	request = kmalloc(sizeof(struct rimbaud_request), GFP_KERNEL);
	if (!request) {
		rc = -ENOMEM;
		goto alloc_failure;
	}

	request->type = GET_BLOB;
	request->transaction_id = readblob.transaction_id;
	request->vsp_response_packet =
		kmalloc(sizeof(struct rimbaud_get_blob_response), GFP_KERNEL);
	if (!request->vsp_response_packet) {
		rc = -ENOMEM;
		goto alloc_failure;
	}

	request->pagevec = pagevec;
	request->num_pages = num_pages;

	atomic_inc(&dev->vsp_pending);
	// send message to VSP
	rc = vmbus_sendpacket_mpb_desc(dev->device->channel,
		payload, payload_sz,
		get_blob_vsp,
		get_blob_vsp->length,
		(unsigned long) request);

	kfree(get_blob_vsp);
	kfree(payload);

	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	blob_remove_vsp_ref(hlist);
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	if (!rc) {
		atomic_dec(&dev->vsp_pending);
		rimbaud_err("vmbus_sendpacket_mpb_desc rc=%d\n", rc);
		return rc;
	}

	return 0;

alloc_failure:

	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	blob_remove_vsp_ref(hlist);
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	for (i=0; i<num_pages; i++) {
		put_page(pagevec[i]);
	}
	kfree(pagevec);
	kfree(payload);

	kfree(get_blob_vsp);
	if (request) {
		kfree(request->vsp_response_packet);
		kfree(request);
	}
	return rc;
}

static int process_client_metadata_hint(
	const char __user *buf, size_t count,
	u16 out_bytes, void __user * response_addr,
	struct rimbaud_device *dev)
{
	struct rimbaud_client_metadata_cache_hint_request metadata_hint;
	struct rimbaud_metadata_hint_request *metadata_hint_vsp = NULL;
	u32 token_len;
	struct rimbaud_request request;
	struct rimbaud_packet_response vsp_response;
	struct rimbaud_client_metadata_cache_hint_response response;
	int rc;
	bool found = false;
	struct blob_handle_hash_list *hlist;
	unsigned long flags;

	if (count < sizeof(metadata_hint) || out_bytes != sizeof(response))
		return -EINVAL;

	rc = copy_from_user(&metadata_hint, buf, sizeof(metadata_hint));
	if (rc)
		return -EPERM;

	token_len = metadata_hint.session_token_length;

	// validate token in the buffer
	if (metadata_hint.session_token_offset + token_len > count) {
		rimbaud_err("token offset %d len %d exceeded packet buffer\n",
			metadata_hint.session_token_offset, token_len);
		return -EINVAL;
	}

	// make sure this blob handle is valid and it's not in closing
	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	hash_for_each_possible(
		dev->read_blob_hash, hlist, node, metadata_hint.blob_handle) {
		if (hlist->blob_handle == metadata_hint.blob_handle) {
			if (!hlist->closing) {
				found = true;
				blob_add_vsp_ref(hlist);
			}
			break;
		}
	}
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	if (!found) {
		rimbaud_err("blob handle %d not found or being closed\n",
			metadata_hint.blob_handle);
		return -EINVAL;
	}

	// prepare VSP message
	metadata_hint_vsp = kmalloc(sizeof(*metadata_hint_vsp) + token_len,
				GFP_KERNEL);
	if (!metadata_hint_vsp) {
		rc = -ENOMEM;
		goto fail;
	}

	metadata_hint_vsp->header.length =
		sizeof(*metadata_hint_vsp) + token_len;
	metadata_hint_vsp->header.blob_handle = metadata_hint.blob_handle;
	metadata_hint_vsp->header.type = CLIENT_METADATA_HINT;
	metadata_hint_vsp->header.timeout = metadata_hint.timeout;
	metadata_hint_vsp->header.transaction_id = metadata_hint.transaction_id;

	// token starts at the end of packet header
	metadata_hint_vsp->header.session_token_offset =
		sizeof(*metadata_hint_vsp);
	metadata_hint_vsp->header.session_token_length = token_len;

	rc = copy_from_user(
		(char *) metadata_hint_vsp +
			metadata_hint_vsp->header.session_token_offset,
		buf + metadata_hint.session_token_offset,
		token_len);
	if (rc) {
		rc = -EPERM;
		goto fail;
	}

	// send a request to VSP and wait for response
	request.vsp_response_packet = &vsp_response;
	request.type = CLIENT_METADATA_HINT;
	init_completion(&request.wait_event);

	atomic_inc(&dev->vsp_pending);
	rc = vmbus_sendpacket(dev->device->channel,
		metadata_hint_vsp,
		metadata_hint_vsp->header.length,
		(unsigned long) &request,
		VM_PKT_DATA_INBAND,
		VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	kfree(metadata_hint_vsp);

	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	blob_remove_vsp_ref(hlist);
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	if (rc) {
		atomic_dec(&dev->vsp_pending);
		return rc;
	}

	rc = wait_for_completion_interruptible(&request.wait_event);
	if (rc) {
		rimbaud_err("wait_for_completion_interruptible rc=%d\n", rc);
		return rc;
	}

	rimbaud_dbg("metadata_hint response length %d status %d\n",
		vsp_response.length, vsp_response.status);

	// write the response to user buf
	response.status = vsp_response.status;
	rc = copy_to_user(response_addr, &response, sizeof(response));

	if (rc)
		rc = -EPERM;

	return rc;

fail:
	kfree(metadata_hint_vsp);

	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	blob_remove_vsp_ref(hlist);
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	return rc;
}

static int process_client_close_blob(
	const char __user *buf, size_t count,
	u16 out_bytes, void __user * response_addr,
	struct rimbaud_device *dev)
{
	struct rimbaud_client_closeblob_request closeblob;
	struct rimbaud_packet_request close_blob_vsp;
	struct rimbaud_request request, *r, *n;
	struct rimbaud_packet_response vsp_response;
	struct rimbaud_client_closeblob_response response;
	int i, rc;
	bool found = false;
	struct blob_handle_hash_list *hlist;
	unsigned long flags;

	if (count < sizeof(closeblob) || out_bytes != sizeof(response))
		return -EINVAL;

	rc = copy_from_user(&closeblob, buf, sizeof(closeblob));
	if (rc)
		return -EPERM;

	// find this blob handle and mark it as closing
	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	hash_for_each_possible(
		dev->read_blob_hash, hlist, node, closeblob.blob_handle) {
		if (hlist->blob_handle == closeblob.blob_handle) {
			if (!hlist->closing) {
				hlist->closing = true;
				found = true;
			}
			break;
		}
	}
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	if (!found) {
		rimbaud_err("can't find blob handle %d or it's being closed\n",
			closeblob.blob_handle);
		return -EINVAL;
	}

	// wait until there is no pending VSP requests on this blob
	wait_event(hlist->wait_close, !READ_ONCE(hlist->vsp_request_pending));

	// send a message to VSP and wait for result
	close_blob_vsp.length = sizeof(close_blob_vsp);
	close_blob_vsp.blob_handle = closeblob.blob_handle;
	close_blob_vsp.type = CLOSE_BLOB;
	close_blob_vsp.timeout = closeblob.timeout;
	close_blob_vsp.transaction_id = closeblob.transaction_id;
	close_blob_vsp.session_token_offset = 0;
	close_blob_vsp.session_token_length = 0;
	
	request.vsp_response_packet = &vsp_response;
	request.type = CLOSE_BLOB;
	init_completion(&request.wait_event);

	atomic_inc(&dev->vsp_pending);
	rc= vmbus_sendpacket(dev->device->channel,
		&close_blob_vsp,
		close_blob_vsp.length,
		(unsigned long) &request,
		VM_PKT_DATA_INBAND,
		VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (rc) {
		rimbaud_err("vmbus_sendpacket rc=%d\n", rc);
		atomic_dec(&dev->vsp_pending);
		return rc;
	}

	rc = wait_for_completion_interruptible(&request.wait_event);
	if (rc) {
		rimbaud_err("wait_for_completion_interruptible rc=%d\n", rc);
		return rc;
	}

	rimbaud_dbg("closeblob response length %d status %d\n",
		vsp_response.length, vsp_response.status);

	//write the blob handle back to user buf
	response.status = vsp_response.status;
	rc = copy_to_user(response_addr, &response, sizeof(response));

	if (rc)
		rc = -EPERM;

	/*
	 * regardless if we have successfully copied the result to user, 
	 * the VSP has closed this handle, so marking it as closed
	 */
	if (!vsp_response.status) {

		wake_up_all(&hlist->wait_response);

		/*
		 * Wait until there is no client get_blob_query pending on
		 * this blob. After this call, it's not possible to have
		 * VSP pending or client pending activities on this blob,
		 * it's safe to delete all its resources
		 */
		wait_event(hlist->wait_close, !READ_ONCE(hlist->query_pending));

		/*
		 * Remove this handle from hashtable and discard all pending
		 * responses for this handle
		 */
		hash_del(&hlist->node);
		list_for_each_entry_safe(r, n, &hlist->head, list) {
			list_del(&r->list);
			for (i = 0; i < r->num_pages; i++)
				put_page(r->pagevec[i]);
			kfree(r->pagevec);
			kfree(r->vsp_response_packet);
			kfree(r);
		}
		kfree(hlist);
	} else {
		rimbaud_err("vsp_response.status = %d\n", vsp_response.status);
		spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
		hlist->closing = false;
		spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);
	}

	return rc;
}

static int process_client_open_blob(
	const char __user *buf, size_t count,
	u16 out_bytes, void __user * response_addr,
	struct rimbaud_device *dev)
{
	struct rimbaud_client_openblob_request openblob;
	u32 token_len, name_len;
	struct rimbaud_open_blob_request *open_blob_vsp = NULL;
	struct rimbaud_request request;
	struct rimbaud_open_blob_response vsp_response;
	int rc;
	struct rimbaud_client_openblob_response response;
	struct blob_handle_hash_list *hash_list;
	unsigned long flags;

	if (count < sizeof(openblob) || out_bytes != sizeof(response))
		return -EINVAL;

	rc = copy_from_user(&openblob, buf, sizeof(openblob));
	if (rc)
		return -EPERM;

	token_len = openblob.session_token_length;
	name_len = openblob.blob_name_length;

	rimbaud_dbg("openblob timeout %d transaction_id %pUl offset %d "
		"length %d token offset %d length %d\n",
		openblob.timeout, &openblob.transaction_id,
		openblob.blob_name_offset, name_len,
		openblob.session_token_offset, token_len);

	// validate token and blob name in the buffer
	if (openblob.blob_name_offset + name_len > count ||
	    openblob.session_token_offset + token_len > count) {
		rimbaud_err("token or name exceeded packet buffer\n");
		return -EINVAL;
	}

	// prepare VSP message to open blob
	open_blob_vsp = kmalloc(sizeof(*open_blob_vsp) + token_len + name_len,
				GFP_KERNEL);
	if (!open_blob_vsp)
		return -ENOMEM;

	open_blob_vsp->header.length =
		sizeof(*open_blob_vsp) + token_len + name_len;
	open_blob_vsp->header.type = OPEN_BLOB;
	open_blob_vsp->header.timeout = openblob.timeout;
	open_blob_vsp->header.transaction_id = openblob.transaction_id;

	// token starts at the end of packet header
	open_blob_vsp->header.session_token_offset =
		sizeof(struct rimbaud_open_blob_request);
	open_blob_vsp->header.session_token_length = token_len;
	rc = copy_from_user(
		(char *) open_blob_vsp +
			open_blob_vsp->header.session_token_offset,
		buf + openblob.session_token_offset,
		token_len);
	if (rc) {
		rc = -EPERM;
		goto fail;
	}

	// blob name starts at the end of token
	open_blob_vsp->blob_name_offset =
		sizeof(struct rimbaud_open_blob_request) + token_len;
	open_blob_vsp->blob_name_length = name_len;
	rc = copy_from_user(
		(char *) open_blob_vsp + open_blob_vsp->blob_name_offset,
		buf + openblob.blob_name_offset,
		name_len);
	if (rc) {
		rc = -EPERM;
		goto fail;
	}

	// send a request to VSP and wait for result
	request.vsp_response_packet = &vsp_response;
	request.type = OPEN_BLOB;
	init_completion(&request.wait_event);

	atomic_inc(&dev->vsp_pending);
	rc= vmbus_sendpacket(dev->device->channel,
		open_blob_vsp,
		open_blob_vsp->header.length,
		(unsigned long) &request,
		VM_PKT_DATA_INBAND,
		VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	kfree(open_blob_vsp);
	// TODO how about ring buffer busy?
	// now simply asking the user-mode to retry
	if (rc) {
		atomic_dec(&dev->vsp_pending);
		return rc;
	}

	rc = wait_for_completion_interruptible(&request.wait_event);
	if (rc) {
		rimbaud_err("wait_for_completion_interruptible rc=%d\n", rc);
		return rc;
	}

	rimbaud_dbg("openblob response length %d status %d handle %d\n",
		vsp_response.header.length, vsp_response.header.status,
		vsp_response.blob_handle);

	/*
	 * prepare hash table for tracking pending responses for this blob
	 * handle. we trust host will not return duplicate blob handles
	 */
	hash_list = kzalloc(sizeof(*hash_list), GFP_KERNEL);
	if (!hash_list)
		return -ENOMEM;

	INIT_LIST_HEAD(&hash_list->head);
	hash_list->blob_handle = vsp_response.blob_handle;

	spin_lock_irqsave(&dev->read_blob_hash_lock, flags);
	hash_add(dev->read_blob_hash, &hash_list->node, hash_list->blob_handle);
	spin_unlock_irqrestore(&dev->read_blob_hash_lock, flags);

	init_waitqueue_head(&hash_list->wait_response);
	init_waitqueue_head(&hash_list->wait_close);

	// write the response to user buf
	response.status = vsp_response.header.status;
	response.blob_handle = vsp_response.blob_handle;
	rc = copy_to_user(response_addr, &response, sizeof(response));
	if (rc)
		rc = -EPERM;

	return rc;

fail:
	kfree(open_blob_vsp);
	return rc;
}

static inline bool rimbaud_safe_file_access(struct file *file)
{
	return file->f_cred == current_cred() && !uaccess_kernel();
}

static ssize_t rimbaud_fop_write(struct file *file, const char __user * buf,
		size_t count, loff_t *pos)
{
	char my_buf[200]; // just for testing, to be removed
	char *write_buf = (void *) buf; //just for testing, to be removed
//	u32 command;
	int rc;
	struct rimbaud_device *dev = file->private_data;
	struct rimbaud_client_request_hdr hdr;
	void __user * response_addr = NULL;

	rimbaud_dbg("count %ld *pos %lld\n", count, *pos);

	if (READ_ONCE(dev->removing))
		return -ENOENT;

	if (!rimbaud_safe_file_access(file)) {
		rimbaud_err("process %d(%s) changed security contexts after"
			" opening file descriptor\n",
			task_tgid_vnr(current), current->comm);
		return -EACCES;
	}

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

	switch(hdr.command) {
		case CLIENT_OPEN_BLOB:
			rc = process_client_open_blob(
				buf + sizeof(hdr),
				count - sizeof(hdr),
				hdr.out_bytes,
				response_addr,
				dev);
			break;

		case CLIENT_CLOSE_BLOB:
			rc = process_client_close_blob(
				buf + sizeof(hdr),
				count - sizeof(hdr),
				hdr.out_bytes,
				response_addr,
				dev);
			break;

		case CLIENT_GET_BLOB:
			rc = process_client_get_blob(
				buf + sizeof(hdr),
				count - sizeof(hdr),
				dev);
			break;

		case CLIENT_GET_BLOB_QUERY:
			rc = process_client_get_blob_query(
				buf + sizeof(hdr),
				count - sizeof(hdr),
				hdr.out_bytes,
				response_addr,
				dev);
			break;

		case CLIENT_METADATA_HINT:
			rc = process_client_metadata_hint(
				buf + sizeof(hdr),
				count - sizeof(hdr),
				hdr.out_bytes,
				response_addr,
				dev);
			break;

		default:
			rc = -ENOENT;
			rimbaud_err("command unknown go to test mode\n");
			goto test_mode;
	}

	if (rc)
		return rc;
	else
		return count;

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
	
	return count;
}

static const struct file_operations rimbaud_client_fops = {
	.owner	= THIS_MODULE,
	.open	= rimbaud_fop_open,
	.write 	= rimbaud_fop_write,
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
	WRITE_ONCE(dev->removing, true);

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

	hash_init(dev->read_blob_hash);
	init_waitqueue_head(&dev->wait_remove);
	atomic_set(&dev->vsp_pending, 0);

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

	ret = vmbus_open(device->channel, ring_size, ring_size, NULL, 0,
			rimbaud_on_channel_callback, device->channel);

	rimbaud_dbg("ret %d\n", ret);
	if (ret)
		return ret;

	rimbaud_dev.device = device;
	hv_set_drvdata(device, &rimbaud_dev);

	return ret;
}

static int rimbaud_negotiate_version(struct rimbaud_device *dev)
{
	struct rimbaud_version_negotiate_request *negotiate_vsp;
	struct rimbaud_request request;
	struct rimbaud_version_negotiate_response vsp_response;
	u32 *major_version, *minor_version;
	int negotiate_vsp_length = sizeof(*negotiate_vsp) + 4;
	int rc;
	
	rimbaud_dbg("negotiating major %u minor %u\n",
		RIMBAUD_VERSION_MAJOR, RIMBAUD_VERSION_MINOR);

	negotiate_vsp = kmalloc(negotiate_vsp_length, GFP_KERNEL);
	if (!negotiate_vsp)
		return -ENOMEM;

	negotiate_vsp->header.length = negotiate_vsp_length;
	negotiate_vsp->header.type = VERSION_NEGOTIATE;
	negotiate_vsp->version_list_offset =
		sizeof(struct rimbaud_version_negotiate_request);
	negotiate_vsp->version_list_length = 4;

	/*
	 * this version of VSC supports one versoin:
	 * RIMBAUD_VERSION_MAJOR, RIMBAUD_VERSION_MINOR
	 */
	major_version = (u32 *)
		((char *)negotiate_vsp + negotiate_vsp->version_list_offset);
	*major_version = RIMBAUD_VERSION_MAJOR;

	minor_version = (u32*)
		((char *)negotiate_vsp + negotiate_vsp->version_list_offset + 2);
	*minor_version = RIMBAUD_VERSION_MINOR;

	// send a message to VSP
	request.vsp_response_packet = &vsp_response;
	request.type = VERSION_NEGOTIATE;
	init_completion(&request.wait_event);

	atomic_inc(&dev->vsp_pending);
	rc = vmbus_sendpacket(dev->device->channel,
		negotiate_vsp,
		negotiate_vsp->header.length,
		(unsigned long) &request,
		VM_PKT_DATA_INBAND,
		VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	kfree(negotiate_vsp);

	if (rc) {
		rimbaud_err("vmbus_sendpacket rc=%d\n", rc);
		atomic_dec(&dev->vsp_pending);
		return rc;
	}

	wait_for_completion(&request.wait_event);
	rimbaud_dbg("negotiate version response major %u minor %u\n",
		vsp_response.selected_major_version,
		vsp_response.selected_minor_version);

	negotiated_version_major = vsp_response.selected_major_version;
	negotiated_version_minor = vsp_response.selected_minor_version;

	// verify if we support VSP selected version
	if (negotiated_version_major != RIMBAUD_VERSION_MAJOR ||
		negotiated_version_minor != RIMBAUD_VERSION_MINOR) {
		rimbaud_err(
			"VSP returned unsupported version major %u minor %u\n",
			negotiated_version_major, negotiated_version_minor);
		return -EINVAL;
	}

	return 0;
}

static void rimbaud_remove_vmbus(struct hv_device *device)
{
	struct rimbaud_device *dev = hv_get_drvdata(device);
	struct blob_handle_hash_list *hlist;
	struct hlist_node *tmp;
	int bkt, i;
	struct rimbaud_request *request, *n;

	wait_event(dev->wait_remove, atomic_read(&dev->vsp_pending) == 0);

	/*
	 * free all the elements in hash table, the user-facing device has
	 * been removed at this point, and it's not possible for VSP returning
	 * something that will change the read_blob_hash table
	 */
	hash_for_each_safe(dev->read_blob_hash, bkt, tmp, hlist, node) {
		list_for_each_entry_safe(request, n, &hlist->head, list) {
			if (request->type == GET_BLOB) {
				for (i=0; i<request->num_pages; i++)
					put_page(request->pagevec[i]);
				kfree(request->pagevec);
				kfree(request->vsp_response_packet);
			}
			kfree(request);
		}
		hash_del(&hlist->node);
		kfree(hlist);
	}

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
// FIXME to enable
#if 0
	rc = rimbaud_negotiate_version(&rimbaud_dev);
	if (rc) {
		rimbaud_err("error negotiating versions rc %d\n", rc);
		rimbaud_remove_vmbus(device);
		return rc;
	}
#endif

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
