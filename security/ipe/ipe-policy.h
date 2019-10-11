/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_POLICY_H
#define IPE_POLICY_H

#include <linux/types.h>
#include "ipe.h"
#include "ipe-hooks.h"
#include "ipe-property.h"

#define IPE_MAX_SUB_RULES 3
#define IPE_MAX_OP_RULES 256

enum ipe_property_value {
	ipe_property_str = 0,
	ipe_property_int,
	ipe_property_bool,
};

struct ipe_sub_rule {
	enum ipe_property_id property_id;
	enum ipe_property_value property_type;
	union {
		char *str_val;
		bool bool_val;
		int int_val;
	};
};

struct ipe_rule {
	bool is_allow_rule;
	size_t sub_rules_count;
	struct ipe_sub_rule sub_rules[IPE_MAX_SUB_RULES];
};

struct ipe_rule_table {
	size_t ipe_rules_count;
	struct ipe_rule ipe_rules[IPE_MAX_OP_RULES];
};

extern struct ipe_rule_table lsm_rules[ipe_hook_max] __ro_after_init;

#endif /* IPE_POLICY_H */
