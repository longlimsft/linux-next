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
 */
typedef bool (*ipe_property_evaluator)(struct ipe_operation_ctx *ctx);


/* Macro for Declaring a Property. */
#define IPE_DECLARE_PROPERTY(property_name) \
	void ipe_get_##property_name(struct ipe_operation_ctx *ctx, \
				     struct file *file); \
	bool ipe_evaluate_##property_name(struct ipe_operation_ctx *ctx) \

/* Macro for Initializing a Property. */
#define IPE_INIT_PROPERTY(property_name) \
	{ \
		.token = ipe_property_##property_name, \
		.populator = ipe_get_##property_name, \
		.evaluator = ipe_evaluate_##property_name, \
	}

enum ipe_property_id {
	ipe_property_dm_verity = 0,
	ipe_property_boot_verified,
	ipe_property_max,
};

/* Property Type Definition */
struct ipe_property {
	enum ipe_property_id token;
	ipe_property_populator populator;
	ipe_property_evaluator evaluator;
};
/*
 * The index of the property evaluator must
 * be the same as the enum value
 *
 * TODO: Build-Time Verification Step of above
 */
extern const struct ipe_property properties[];


IPE_DECLARE_PROPERTY(dm_verity);
IPE_DECLARE_PROPERTY(boot_verified);

#endif /* IPE_PROPERTY_H */
