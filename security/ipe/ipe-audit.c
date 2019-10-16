// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include <linux/sched.h>
#include "ipe-audit.h"

#define BOOLTOSTR(b) (b) ? "true" : "false"

const char *const operation_names[] = { "execute", "kernel_read" };

const char *const hook_names[] = {
	"exec",
	"mmap",
	"kernel_read",
	"kernel_load_data",
	"mprotect"
};

static void ipe_audit_ctx(struct audit_buffer *ab,
			  struct ipe_operation_ctx *ctx)
{
	char comm[sizeof(current->comm)];
	int err;

	audit_log_format(ab, "ctx ( ");

	/*
	 * The following two audit values are copied from
	 * dump_common_audit_data
	 */
	audit_log_format(ab, "pid: [%d] comm: [", task_tgid_nr(current));

	/* This is indicated as comm, but it appears to be the proc name */
	audit_log_untrustedstring(ab,
		memcpy(comm, current->comm, sizeof(comm)));

	audit_log_format(ab, "] ");

	audit_log_format(ab, "op: [%s] ", operation_names[ctx->op]);

	audit_log_format(ab, "hook: [%s] ", hook_names[ctx->hook]);

	audit_log_format(ab, "dmverity_verified: [%s] ",
			 BOOLTOSTR(ctx->dm_verity_verified));

	audit_log_format(ab, "boot_verified: [%s] ",
			 BOOLTOSTR(ctx->boot_verified));

	/* On failure to acquire audit_pathname, log the error code */


	if (IS_ERR(ctx->audit_pathname)) {
		err = PTR_ERR(ctx->audit_pathname);
		switch (err) {
		case -ENOENT:
			break;
		default:
			audit_log_format(ab, "audit_pathname: ");
			audit_log_format(ab, "[ERR(%ld)] ",
				PTR_ERR(ctx->audit_pathname));
		}
	} else
		audit_log_format(ab, "audit_pathname: [%s] ",
			ctx->audit_pathname);

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

	if (is_boot_verified && success_audit)
		audit_log_format(ab,
				 " [ action = %s ] [ boot_verified = %s ]",
				 "allow",
				 "true");
	else if (is_dmverity_verified && success_audit)
		audit_log_format(ab,
				 " [ action = %s ] [ dmverity_verified = %s ]",
				 "allow",
				 "true");
	else
		audit_log_format(ab, " [ action = deny ]");

	audit_log_end(ab);
}
