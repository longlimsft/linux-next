/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_PROPERTY_H
#define IPE_PROPERTY_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/parser.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include "ipe.h"

#define IPE_PROPERTY_VALUE_FALSE "F"
#define IPE_PROPERTY_VALUE_TRUE "T"

/* Forward Declarations */
struct ipe_operation_ctx;
struct ipe_sub_rule;
struct ipe_rule_ctx;

/*
 * Populator Prototype. Populates the operation ctx with
 * necessary fields of the evaluator.  Developers should
 * be aware that this function is called lazily, and as
 * such it may be called multiple times.
 *
 * @ctx - Context pointer to be populated with necessary
 *     information needed in the evaluator.
 * @file - File object to derive necessary information
 *     from.
 */
typedef void (*ipe_property_populator)(struct ipe_operation_ctx *ctx,
				       struct file *file);

/*
 * Evaluator Prototype. Returns true on successful match
 * false otherwise.
 *
 * @ctx - Context containing information required to
 *      determine whether a property is a match or not.
 * @sub_rule - The portion of the policy that contains
 *      the value to compare against.
 */
typedef bool (*ipe_property_evaluator)(struct ipe_operation_ctx *ctx,
				       struct ipe_sub_rule *sub_rule);

/*
 * Property Audit Prototype. Appends to the audit_buffer with
 * the string representation of the property. Best-Effort.
 *
 * @ab - Audit Buffer that should be used as the parameter
 *     to audit_log_format
 * @property - The associated rule that should be transformed
 *     into a string.
 */
typedef void (*ipe_property_audit_formatter)(struct audit_buffer *ab,
					     struct ipe_sub_rule *property);

/*
 * Property Initialization. This is called in init of IPE.
 *   Properties are required to call the Macro, IPE_REGISTER_PROPERTY
 *   During this function.
 *
 *  Return Value: True if Initialization Succeeds, False Otherwise.
 */
typedef bool (*ipe_property_init)(void);

/*
 * Rule Parser. This is called by the parsing engine when the
 *   Registered token is found to transform the string into a
 *   rule value.
 *
 * @token_value - the string representation of the token to be
 *  interpreted into a rule value.
 * @rule - The rule to be populated with the proper representation
 *  of the token.
 *
 * Return Value: Error Code
 */
typedef int (*ipe_property_rule_parser)(const char *token_value,
					struct ipe_sub_rule *rule);

/* Macro for Declaring a Property. */
#define IPE_DECLARE_PROPERTY(property_name) \
	void ipe_get_##property_name(struct ipe_operation_ctx *ctx, \
				     struct file *file); \
	bool ipe_evaluate_##property_name(struct ipe_operation_ctx *ctx, \
					  struct ipe_sub_rule *sub_rule); \
	void ipe_audit_##property_name(struct audit_buffer *ab, \
				       struct ipe_sub_rule *property); \
	bool ipe_init_##property_name(void); \
	int ipe_parse_##property_name(const char *token_value, \
				      struct ipe_sub_rule *rule)

/* Macro for Initializing a Property. */
#define IPE_INIT_PROPERTY(property_name) \
	{ \
		.token = ipe_property_##property_name, \
		.populator = ipe_get_##property_name, \
		.evaluator = ipe_evaluate_##property_name, \
		.init = ipe_init_##property_name, \
		.parser = ipe_parse_##property_name, \
		.auditor = ipe_audit_##property_name, \
	}

#define IPE_REGISTER_PROPERTY(property_name, parse_syntax) \
	ipe_property_table[ipe_property_##property_name].token = \
		ipe_property_##property_name; \
	ipe_property_table[ipe_property_##property_name].pattern = parse_syntax

enum ipe_property_id {
	ipe_property_dm_verity = 0,
	ipe_property_kernel_subj,
	ipe_property_boot_verified,
	ipe_property_max,
};

/* Property Type Definition */
struct ipe_property {
	enum ipe_property_id token;
	ipe_property_populator populator;
	ipe_property_evaluator evaluator;
	ipe_property_audit_formatter auditor;
	ipe_property_init init;
	ipe_property_rule_parser parser;
};
/*
 * The index of the property evaluator must
 * be the same as the enum value
 *
 * TODO: Build-Time Verification Step of above
 */
extern const struct ipe_property properties[];

/*
 * 2nd Level Table Used for Matching Property Keys
 */
extern struct match_token ipe_property_table[ipe_property_max + 1];

IPE_DECLARE_PROPERTY(dm_verity);
IPE_DECLARE_PROPERTY(kernel_subj);
IPE_DECLARE_PROPERTY(boot_verified);

#endif /* IPE_PROPERTY_H */
