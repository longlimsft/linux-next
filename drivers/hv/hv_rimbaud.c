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
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/hyperv.h>
#include <linux/blkdev.h>

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
