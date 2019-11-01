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
#include "ipe-audit.h"

/*
 * Function that represents the entry point of an exec call
 */
int ipe_on_exec(struct linux_binprm *bprm)
{
	return ipe_process_event(ipe_operation_execute, ipe_hook_exec,
				 bprm->file);
}

/*
 * Function that represents the entry point of a mmap call
 */
int ipe_on_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		unsigned long flags)
{
	/*
	 * If no executable flag set, allow load
	 */
	if (!(reqprot & PROT_EXEC) || !(prot & PROT_EXEC))
		return 0;

	/* Overlake *Temporary* Errata: Anonymous Memory is Allowed */
	if (flags & MAP_ANONYMOUS) {
		/*
		 * This is still technically a failure, and should
		 * be audited as such
		 */
		ipe_audit_anon_mem_exec();
		return 0;
	}

	return ipe_process_event(ipe_operation_execute, ipe_hook_mmap, file);
}

/*
 * Function called for mprotect
 */
int ipe_on_set_executable(struct vm_area_struct *vma, unsigned long reqprot,
			  unsigned long prot)
{
	/* mmap already flagged as executable */
	if (vma->vm_flags & VM_EXEC)
		return 0;

	/*
	 * If no executable flag set, allow load
	 */
	if (!(reqprot & PROT_EXEC) || !(prot & PROT_EXEC))
		return 0;

	return ipe_process_event(ipe_operation_execute,
				 ipe_hook_mprotect, vma->vm_file);
}

/*
 * Function for loading anything into kernel memory
 */
int ipe_on_kernel_read(struct file *file, enum kernel_read_file_id id)
{

	/* Overlake Errata: KEXEC / INITRAMFS are signed by IMA / FIT */
	switch (id) {
	case READING_KEXEC_IMAGE:
	case READING_KEXEC_INITRAMFS:
		return 0;
	default:
		break;
	}

	return ipe_process_event(ipe_operation_kernel_read,
				 ipe_hook_kernel_read, file);
}

/*
 * This LSM uses the kernel object to make decisions about enforcement.
 * This hook does not have any such structs available to it, so this is
 * disabled while this LSM is active on the system. As a result, all
 * kernel reads must come from a file.
 */
int ipe_on_kernel_load_data(enum kernel_load_data_id id)
{
	return ipe_process_event(ipe_operation_kernel_read,
				 ipe_hook_kernel_load_data, NULL);
}

/*
 * Function called on super block unmount
 */
void ipe_sb_free_security(struct super_block *mnt_sb)
{
	ipe_invalidate_pinned_sb(mnt_sb);
}
