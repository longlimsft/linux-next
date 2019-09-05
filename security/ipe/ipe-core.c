// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
#include <linux/mount.h>
#include <linux/binfmts.h>
#include <linux/magic.h>
#include "ipe.h"
#include "ipe-hooks.h"
#include "ipe-property.h"
#include "ipe-policy.h"
#include "ipe-audit.h"
#include "ipe-pin.h"

struct ipe_rule_table lsm_rules[ipe_hook_max] __ro_after_init;

static void ipe_free_ctx(struct ipe_operation_ctx *ctx)
{
	/* __putname does not NULL check the free */
	if (ctx->audit_pathname)
		__putname(ctx->audit_pathname);
	ctx->audit_pathname = NULL;
}

/*
 * Function to get the absolute pathname of a file, and populate that in ctx
 */
static void ipe_get_audit_pathname(struct ipe_operation_ctx *ctx,
				   struct file *file)
{
	char *pathbuf = NULL;
	char *temp_path = NULL;
	char *pos = NULL;
	struct dentry *dentry;
	struct super_block *sb;

	/* No File to get Path From */
	if (file == NULL)
		return;

	dentry = file->f_path.dentry;

	/* No backing entry */
	if (!dentry)
		return;

	sb = dentry->d_sb;

	/* a socket */
	if (sb->s_magic == SOCKFS_MAGIC)
		return;

	/* a pipe */
	if (dentry->d_op && dentry->d_op->d_dname)
		return;

	pathbuf = __getname();
	if (!pathbuf)
		goto err;

	pos = d_absolute_path(&file->f_path, pathbuf, PATH_MAX);
	if (IS_ERR(pos))
		goto err;

	temp_path = __getname();
	if (!temp_path)
		goto err;

	if (strlcpy(temp_path, pos, PATH_MAX) >= PATH_MAX)
		goto err;

	/* Transfer Buffer */
	ctx->audit_pathname = temp_path;
	temp_path = NULL;
err:
	if (pathbuf)
		__putname(pathbuf);
	if (temp_path)
		__putname(temp_path);
}

/*
 *	Based on the rules, and a populated ctx structure,
 *	determine whether the call should be blocked, or
 *	allowed to pass.
 *	Returns -EACCES when the call should be blocked.
 */
static int ipe_apply_rules(struct ipe_operation_ctx *ctx,
			   struct ipe_rule_table *rules_table,
			   struct file *file)
{
	bool rule_match;
	size_t i;
	size_t j;
	struct ipe_rule *rule;
	struct ipe_sub_rule *sub_rule;

	ipe_get_audit_pathname(ctx, file);

	for (i = 0; i < rules_table->ipe_rules_count; ++i) {
		rule = &rules_table->ipe_rules[i];
		rule_match = true;
		for (j = 0; j < rule->sub_rules_count && rule_match; ++j) {
			sub_rule = &rule->sub_rules[j];

			/*
			 * Call Related Populator (if Already Populated,
			 * should no-op)
			 */
			properties[sub_rule->property_id].populator(ctx, file);

			if (!properties[sub_rule->property_id].evaluator(
				    ctx, sub_rule))
				rule_match = false;
		}

		/*
		 * if the rule matched, and the rule
		 * is a deny rule, short circuit with -EACCES
		 */
		if (rule_match && !rule->is_allow_rule) {
			ipe_audit_message(ctx, rule);
			if (!enforce)
				return 0;
			return -EACCES;
		}

		/*
		 * if the rule matched, and didn't exit above,
		 * then it's an allow rule, and should exit with 0.
		 */
		if (rule_match) {
			if (success_audit)
				ipe_audit_message(ctx, rule);
			return 0;
		}
	}

	/* if no rules matched, return -EACCES */
	ipe_audit_message(ctx, NULL);
	if (!enforce)
		return 0;

	return -EACCES;
}

/*
 * This function will check the current context against the policy and
 * return success if the policy allows it and returns a -EACCES if the policy
 * blocks it.
 */
int ipe_process_event(struct ipe_operation_ctx *ctx, struct file *file)
{
	int rc = 0;

	rc = ipe_apply_rules(ctx, &lsm_rules[ctx->op], file);

	ipe_free_ctx(ctx);

	return rc;
}
