// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include "ipe-audit.h"

#define BOOLTOSTR(b) (b) ? "true" : "false"

const char *hook_names[] = { "execute", "kernel_read" };

static void ipe_audit_ctx(struct audit_buffer *ab,
			  struct ipe_operation_ctx *ctx)
{
	audit_log_format(ab, "ctx ( op: [%s] ", hook_names[ctx->op]);

	audit_log_format(ab, "dmverity_verified: [%s] ",
			 BOOLTOSTR(ctx->dm_verity_verified));

	audit_log_format(ab, "boot_verified: [%s] ",
			 BOOLTOSTR(ctx->boot_verified));

	audit_log_format(ab, "audit_pathname: [%s] ", ctx->audit_pathname);

	audit_log_format(ab, ") ");
}

void ipe_audit_message(struct ipe_operation_ctx *ctx, bool is_boot_verified,
		       bool is_dmverity_verified)
{
	struct audit_buffer *ab;

	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_INTEGRITY_POLICY_RULE);
	if (!ab)
		return;

	audit_log_format(ab, "IPE=");

	ipe_audit_ctx(ab, ctx);

	if (is_boot_verified)
		audit_log_format(ab,
				 " [ action = %s ] [ boot_verified = %s ]",
				 "allow",
				 "true");
	else if (is_dmverity_verified)
		audit_log_format(ab,
				 " [ action = %s ] [ dmverity_verified = %s ]",
				 "allow",
				 "true");
	else
		audit_log_format(ab, " [ action = deny ]");

	audit_log_end(ab);
}
