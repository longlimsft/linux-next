// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include <linux/device-mapper.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include "ipe.h"
#include "ipe-hooks.h"
#include "ipe-core.h"
#include "ipe-pin.h"

/*
 * Function that represents the entry point of a mmap call
 */
int ipe_on_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		unsigned long flags)
{
	struct ipe_operation_ctx ctx = {
		.op = ipe_operation_execute,
		.hook = ipe_hook_mmap
	};

	/*
	 * If no executable flag set, allow load
	 */
	if (!(reqprot & PROT_EXEC) || !(prot & PROT_EXEC))
		return 0;

	return ipe_process_event(&ctx, file);
}

/*
 * Function that represents the entry point of an exec call
 */
int ipe_on_exec(struct linux_binprm *bprm)
{
	struct ipe_operation_ctx ctx = {
		.op = ipe_operation_execute,
		.hook = ipe_hook_exec
	};

	return ipe_process_event(&ctx, bprm->file);
}

/*
 * Function for loading anything into kernel memory
 */
int ipe_on_kernel_read(struct file *file, enum kernel_read_file_id id)
{
	struct ipe_operation_ctx ctx = {
		.op = ipe_operation_kernel_read,
		.hook = ipe_hook_kernel_read
	};

	return ipe_process_event(&ctx, file);
}

/*
 * This LSM uses the kernel object to make decisions about enforcement.
 * This hook does not have any such structs available to it, so this is
 * disabled while this LSM is active on the system. As a result, all
 * kernel reads must come from a file.
 */
int ipe_on_kernel_load_data(enum kernel_load_data_id id)
{
	struct ipe_operation_ctx ctx = {
		.op = ipe_operation_kernel_read,
		.hook = ipe_hook_kernel_load_data
	};

	return ipe_process_event(&ctx, NULL);
}

/*
 * Function called for mprotect
 */
int ipe_on_set_executable(struct vm_area_struct *vma, unsigned long reqprot,
			  unsigned long prot)
{
	struct ipe_operation_ctx ctx = {
		.op = ipe_operation_execute,
		.hook = ipe_hook_mprotect
	};

	/* mmap already flagged as executable */
	if (vma->vm_flags & VM_EXEC)
		return 0;

	/*
	 * If no executable flag set, allow load
	 */
	if (!(reqprot & PROT_EXEC) || !(prot & PROT_EXEC))
		return 0;

	return ipe_process_event(&ctx, vma->vm_file);
}

/*
 * Function called on super block unmount
 */
void ipe_sb_free_security(struct super_block *mnt_sb)
{
	ipe_invalidate_pinned_sb(mnt_sb);
}
