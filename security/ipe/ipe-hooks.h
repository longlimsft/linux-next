/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_HOOKS_H
#define IPE_HOOKS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/binfmts.h>

enum ipe_operation {
	ipe_operation_execute = 0,
	ipe_operation_kernel_read,
	ipe_operation_max
};

enum ipe_hook {
	ipe_hook_exec = 0,
	ipe_hook_mmap,
	ipe_hook_kernel_read,
	ipe_hook_kernel_load_data,
	ipe_hook_mprotect,
	ipe_hook_max
};

int ipe_on_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		unsigned long flags);

int ipe_on_exec(struct linux_binprm *bprm);

int ipe_on_kernel_read(struct file *file, enum kernel_read_file_id);

int ipe_on_kernel_load_data(enum kernel_load_data_id id);

int ipe_on_set_executable(struct vm_area_struct *vma, unsigned long reqprot,
			  unsigned long prot);

void ipe_sb_free_security(struct super_block *mnt_sb);

#endif /* IPE_HOOKS_H */
