// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2009, Microsoft Corporation.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 *   K. Y. Srinivasan <kys@microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/hyperv.h>

enum rimbaud_request_type {
	rimbaud_open_blob		= 1,
	rimbaud_close_blob		= 2,
	rimbaud_metadata_cache_hint	= 3,
	rimbaud_get_glob		= 4,
	rimbaud_update_session		= 5
};

// Header for all rimbaud request packets
struct rimbaud_packet_request {
	u32	length;
	u32	blob_handle;

	// The request type defined by enum rimbaud_request_type
	u32	type;

	// Request timeout in milliseconds
	u32	timeout;
	guid_t	transaction_id;

	// Offset into the packet buffer for the sessin token
	u32	session_token_offset;
	u32	session_token_length;
} __packed;

struct rimbaud_open_blob_request {
	struct rimbaud_packet_request header;

	// Offset into the packet buffer for the blob name
	u32	blob_name_offset;
	u32	blob_name_length;
} __packed;

struct rimbaud_metadata_hint_request {
	struct rimbaud_packet_request header;

	// Offset into the blob where cached metadata should start
	u64	offset;

	// Length of the blob section to cache metadata
	u64	length;
} __packed;

struct rimbaud_get_blob_request {
	struct rimbaud_packet_request header;

	// Request flags
	union {
		u32	all_flags;
		struct {
			u8	guest_compress : 1;
			u8	guest_encrypt : 1;
		};
	};

	// Offset into the blob to read
	u64 offset;

	// Length of the blob section to read
	u32 length;
} __packed;

// Header for rimbaud response packets
struct rimbaud_packet_response {
	u32	length;
	u32	status;
} __packed;

struct rimbaud_open_blob_response {
	struct rimbaud_packet_response header;
	u32 blob_handle;
} __packed;

struct rimbaud_get_blob_response {
	struct rimbaud_packet_response header;

	// Bytes written to data buffer
	u32	bytes_written;

	// Starting offset into the blob for returned data
	u64	blob_offset;
} __packed;

static int rimbaud_ringbuffer_size = (128 * 1024);

static const struct hv_vmbus_device_id id_table[] = {
	{ HV_RIMBAUD_GUID,
	  .driver_data = 0
	},
	{ },
};

static void rimbaud_on_channel_callback(void *context)
{

}

int rimbaud_channel_init(struct hv_device *device)
{
	return 0;
}

static int rimbaud_connect_to_vsp(struct hv_device *device, u32 ring_size)
{
	int ret;

	ret = vmbus_open(device->channel, ring_size, ring_size, NULL, 0,
			rimbaud_on_channel_callback, device->channel);

	printk(KERN_ERR "%s: ret %d\n", __func__, ret);
	if (ret)
		return ret;

	ret = rimbaud_channel_init(device);

	return ret;
}

static int rimbaud_probe(struct hv_device *device,
			const struct hv_vmbus_device_id *dev_id)
{
	printk(KERN_ERR "LL %s\n", __func__);
	rimbaud_connect_to_vsp(device, rimbaud_ringbuffer_size);
	return 0;
}

static int rimbaud_remove(struct hv_device *dev)
{
	printk(KERN_ERR "LL %s\n", __func__);
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
	int ret;

	ret = vmbus_driver_register(&rimbaud_drv);

	return ret;
}

static void __exit rimbaud_drv_exit(void)
{
	vmbus_driver_unregister(&rimbaud_drv);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Microsoft Azure Rimbaud storage driver");
module_init(rimbaud_drv_init);
module_exit(rimbaud_drv_exit);
