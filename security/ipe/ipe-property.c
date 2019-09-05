// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include "ipe.h"
#include "ipe-property.h"
#include "ipe-pin.h"

struct match_token ipe_property_table[ipe_property_max + 1] = { 0 };

const struct ipe_property properties[] = {
	IPE_INIT_PROPERTY(dm_verity),
	IPE_INIT_PROPERTY(kernel_subj),
	IPE_INIT_PROPERTY(boot_verified),
};
