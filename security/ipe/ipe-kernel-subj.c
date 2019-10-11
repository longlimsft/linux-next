// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/types.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include "ipe.h"
#include "ipe-property.h"
#include "ipe-policy.h"
#include "ipe-audit.h"
#include "ipe-kernel-subj.h"

struct kernel_subj_map {
	enum ipe_kernel_subject subj;
	const char *subj_name;
};

static struct kernel_subj_map subj_mapping[] = {
	{ ipe_kernel_subj_firmware, "firmware" },
	{ ipe_kernel_subj_module, "module" },
	{ ipe_kernel_subj_kexec_image, "kernel" },
	{ ipe_kernel_subj_kexec_initramfs, "initramfs" },
	{ ipe_kernel_subj_policy, "policy" },
	{ ipe_kernel_subj_certificate, "certificate" },
};

static int ipe_get_kernel_subj_mapping(const char *subj_name,
				       enum ipe_kernel_subject *subj)
{
	size_t i;

	if (subj_name == NULL || subj == NULL)
		return -EINVAL;

	for (i = 0; i < sizeof(subj_mapping); i++) {
		if (strcmp(subj_mapping[i].subj_name, subj_name) == 0) {
			*subj = subj_mapping[i].subj;
			return 0;
		}
	}

	return -ENOENT;
}

/* NO-OP. This Property is set by the hooks themselves. */
void ipe_get_kernel_subj(struct ipe_operation_ctx *ctx, struct file *file)
{
}

bool ipe_evaluate_kernel_subj(struct ipe_operation_ctx *ctx,
			      struct ipe_sub_rule *sub_rule)
{
	/*
	 * Only Kernel Reads are applicable to this property.
	 * everything else should just pass this property
	 * if it is specified
	 */
	if (ctx->op != ipe_hook_kernel_read)
		return true;

	return ctx->what == (enum ipe_kernel_subject)sub_rule->int_val;
}

bool ipe_init_kernel_subj(void)
{
	IPE_REGISTER_PROPERTY(kernel_subj, "what=%s");

	return true;
}

int ipe_parse_kernel_subj(const char *token_value, struct ipe_sub_rule *rule)
{
	enum ipe_kernel_subject subj;
	int rc = 0;

	rule->property_id = ipe_property_kernel_subj;
	rule->property_type = ipe_property_int;

	rc = ipe_get_kernel_subj_mapping(token_value, &subj);
	if (!rc)
		rule->int_val = subj;

	return rc;
}

void ipe_audit_kernel_subj(struct audit_buffer *ab,
			   struct ipe_sub_rule *property)
{
	audit_log_format(ab, "[ what = %s ]", subj_names[property->int_val]);
}
