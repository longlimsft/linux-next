// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include "ipe-audit.h"
#include "ipe-kernel-subj.h"

#define BOOLTOSTR(b) b ? "true" : "false"

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

	if (ctx->op == ipe_hook_kernel_read)
		audit_log_format(ab, "what: [%s] ", subj_names[ctx->what]);

	audit_log_format(ab, ") ");
}

static void ipe_audit_rule(struct audit_buffer *ab, struct ipe_rule *rule)
{
	size_t i = 0;

	audit_log_format(ab, "rule ( ");

	if (rule != NULL) {
		for (i = 0; i < rule->sub_rules_count; ++i) {
			struct ipe_sub_rule *sub_rule = &rule->sub_rules[i];

			properties[sub_rule->property_id].auditor(ab, sub_rule);
			audit_log_format(ab, " ");
		}
		audit_log_format(ab, "[ action = %s ] ",
				 rule->is_allow_rule ? "allow" : "deny");
	} else
		audit_log_format(ab, "default [ action = deny ]");

	audit_log_format(ab, " )");
}

void ipe_audit_message(struct ipe_operation_ctx *ctx,
		       struct ipe_rule *matched_rule)
{
	struct audit_buffer *ab;

	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_INTEGRITY_POLICY_RULE);
	if (!ab)
		return;

	audit_log_format(ab, "IPE=");

	ipe_audit_ctx(ab, ctx);

	ipe_audit_rule(ab, matched_rule);

	audit_log_end(ab);
}
