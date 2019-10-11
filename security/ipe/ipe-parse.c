// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include "ipe.h"
#include "ipe-property.h"
#include "ipe-parse.h"
#include "ipe-hooks.h"

#define ALLOW "allow"
#define DENY "deny"

/* Local Enum Definitions */
enum ipe_policy_options {
	ipe_option_operation = 0,
	ipe_option_action,
	ipe_option_property,
};

/* Local Struct Definitions */
struct ipe_rule_ctx {
	enum ipe_hook op;
	struct ipe_rule rule;
};

struct operation_mapping {
	enum ipe_hook op;
	const char *operation_name;
};

/* Globals */
static const char *const rule_table[] = {
	"operation=execute dmverity_verified=T action=allow",
	"operation=execute boot_verified=T action=allow",
	"operation=kernel_read dmverity_verified=T action=allow",
	"operation=kernel_read boot_verified=T action=allow",
};

static match_table_t policy_tokens = {
	{ ipe_option_operation, "operation=%s" },
	{ ipe_option_action, "action=%s" },
	{ ipe_option_property, NULL },
};

static struct operation_mapping ops_table[] = {
	{ ipe_hook_execute, "execute" },
	{ ipe_hook_kernel_read, "kernel_read" },
};

static int ipe_get_operation_table_mapping(char *operation_name,
					   enum ipe_hook *op)
{
	size_t i;

	if (operation_name == NULL || op == NULL)
		return -EINVAL;

	for (i = 0; i < sizeof(ops_table); i++) {
		if (strcmp(ops_table[i].operation_name, operation_name) == 0) {
			*op = ops_table[i].op;
			return 0;
		}
	}

	return -ENOENT;
}

static int ipe_get_rule_type(char *action, bool *is_allow_rule)
{
	if (strcmp(action, ALLOW) == 0)
		*is_allow_rule = true;
	else if (strcmp(action, DENY) == 0)
		*is_allow_rule = false;
	else
		return -EINVAL;

	return 0;
}

static int ipe_add_op(char *token_value, struct ipe_rule_ctx *rule_ctx)
{
	if (token_value == NULL)
		return -EINVAL;

	return ipe_get_operation_table_mapping(token_value, &rule_ctx->op);
}

static int ipe_set_action(char *token_value, struct ipe_rule_ctx *rule_ctx)
{
	if (token_value == NULL)
		return -EINVAL;

	return ipe_get_rule_type(token_value, &rule_ctx->rule.is_allow_rule);
}

static int ipe_parse_property(char *p, substring_t args[],
			      struct ipe_sub_rule *rule)
{
	enum ipe_property_id property;

	property =
		(enum ipe_property_id)match_token(p, ipe_property_table, args);
	if (property == ipe_property_max)
		return -ENOENT;

	pr_err("Property: %d", property);

	return properties[property].parser(args[0].from, rule);
}

static void ipe_add_to_table(struct ipe_rule *rule, enum ipe_hook op)
{
	struct ipe_rule_table *operation_rules = &lsm_rules[op];

	operation_rules->ipe_rules[operation_rules->ipe_rules_count++] = *rule;
}

static int ipe_parse_add_rule(const char *policy_item)
{
	char *p;
	int rc = 0;
	struct ipe_rule_ctx rule_ctx = { 0 };
	char *local_policy_item = NULL;
	const char *free_item = NULL;

	local_policy_item = kstrdup(policy_item, GFP_KERNEL);
	if (local_policy_item == NULL) {
		rc = -ENOMEM;
		goto cleanup;
	}

	/* Store the address to be freed */
	free_item = local_policy_item;

	while ((p = strsep(&local_policy_item, " ")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		enum ipe_policy_options token;
		struct ipe_sub_rule *sub_rule = NULL;

		if (rule_ctx.rule.sub_rules_count >= IPE_MAX_SUB_RULES) {
			rc = -EINVAL;
			goto cleanup;
		}

		if ((*p == '\0') || (*p == ' ' || (*p == '\t')))
			continue;

		token = (enum ipe_policy_options)match_token(p, policy_tokens,
							     args);

		sub_rule =
			&rule_ctx.rule.sub_rules[rule_ctx.rule.sub_rules_count];

		/* Determine Operation/Action/Property */
		switch (token) {
		case ipe_option_operation:
			rc = ipe_add_op(args[0].from, &rule_ctx);
			if (rc)
				goto cleanup;
			break;
		case ipe_option_action:
			rc = ipe_set_action(args[0].from, &rule_ctx);
			if (rc)
				goto cleanup;
			break;
		case ipe_option_property:
			rc = ipe_parse_property(p, args, sub_rule);
			if (rc)
				goto cleanup;
			++rule_ctx.rule.sub_rules_count;
			break;
		default:
			rc = -ENOENT;
			goto cleanup;
		}
	}

	ipe_add_to_table(&rule_ctx.rule, rule_ctx.op);
cleanup:
	kfree(free_item);
	return rc;
}

static void ipe_rules_cleanup(void)
{
	size_t i = 0;
	size_t j = 0;
	size_t k = 0;

	for (i = 0; i < ARRAY_SIZE(lsm_rules); i++) {
		for (j = 0; j < lsm_rules[i].ipe_rules_count; j++) {
			for (k = 0;
			     k < lsm_rules[i].ipe_rules[j].sub_rules_count;
			     k++) {
				if (lsm_rules[i]
					    .ipe_rules[j]
					    .sub_rules[k]
					    .property_type == ipe_property_str)

					kfree(lsm_rules[i]
						      .ipe_rules[j]
						      .sub_rules[k]
						      .str_val);
			}
		}
	}
}
int ipe_load_policy(void)
{
	size_t i;
	int rc = 0;

	for (i = 0; i < ARRAY_SIZE(rule_table); i++) {
		rc = ipe_parse_add_rule(rule_table[i]);
		if (rc) {
			ipe_rules_cleanup();
			return rc;
		}
	}

	return rc;
}
