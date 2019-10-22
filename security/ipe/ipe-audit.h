/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_AUDIT_H
#define IPE_AUDIT_H

#include <linux/types.h>
#include <linux/lsm_audit.h>
#include "ipe.h"

void ipe_audit_message(struct ipe_operation_ctx *ctx, bool is_boot_verified,
					   bool is_dmverity_verified);

void ipe_build_audit_data(struct ipe_audit_data *audit_data, struct file *file);

void ipe_audit_mode_change(void);

#endif /* IPE_AUDIT_H */
