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

#endif /* IPE_AUDIT_H */
