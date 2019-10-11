/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_H
#define IPE_H

#include <linux/types.h>
#include <linux/fs.h>
#include "ipe-hooks.h"
#include "ipe-policy.h"

extern int enforce;
extern int success_audit;

enum ipe_kernel_subject {
	ipe_kernel_subj_unknown = 0,
	ipe_kernel_subj_firmware,
	ipe_kernel_subj_module,
	ipe_kernel_subj_kexec_image,
	ipe_kernel_subj_kexec_initramfs,
	ipe_kernel_subj_policy,
	ipe_kernel_subj_certificate,
};

struct ipe_operation_ctx {
	enum ipe_hook op;
	enum ipe_kernel_subject what;
	bool dm_verity_verified;
	bool boot_verified;
	char *audit_pathname;
};

#endif /* IPE_H */
