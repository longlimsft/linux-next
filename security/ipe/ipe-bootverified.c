// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/mount.h>
#include "ipe.h"
#include "ipe-pin.h"
#include "ipe-property.h"

void ipe_get_boot_verified(struct ipe_operation_ctx *ctx, struct file *file)
{
	ctx->boot_verified = false;
	/*
	 * If we hit a null pointer until we get to the superblock,
	 * this path is considered unverified
	 */
	if (!file || !file->f_path.mnt->mnt_sb)
		return;

	ipe_pin_superblock(file);

	ctx->boot_verified = ipe_is_from_pinned_sb(file);
}

bool ipe_evaluate_boot_verified(struct ipe_operation_ctx *ctx,
				struct ipe_sub_rule *sub_rule)
{
	return ctx->boot_verified == sub_rule->bool_val;
}

void ipe_audit_boot_verified(struct audit_buffer *ab,
			     struct ipe_sub_rule *property)
{
	audit_log_format(ab, "[ boot_verified = %s ]",
			 property->bool_val ? "true" : "false");
}

bool ipe_init_boot_verified(void)
{
	IPE_REGISTER_PROPERTY(boot_verified, "boot_verified=%s");

	return true;
}

int ipe_parse_boot_verified(const char *token_value, struct ipe_sub_rule *rule)
{
	rule->property_id = ipe_property_boot_verified;
	rule->property_type = ipe_property_bool;

	if (strcmp(token_value, IPE_PROPERTY_VALUE_FALSE) == 0)
		rule->bool_val = false;
	else if (strcmp(token_value, IPE_PROPERTY_VALUE_TRUE) == 0)
		rule->bool_val = true;
	else
		return -EINVAL;

	return 0;
}
