/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_AUDIT_H
#define IPE_AUDIT_H

#include <linux/types.h>
#include <linux/lsm_audit.h>
#include "ipe.h"
#include "ipe-policy.h"

void ipe_audit_message(struct ipe_operation_ctx *ctx,
		       struct ipe_rule *matched_rule);

#endif /* IPE_AUDIT_H */
