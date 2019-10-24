// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#define pr_fmt(fmt) "IPE: " fmt

#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include "ipe.h"
#include "ipe-property.h"
#include "ipe-hooks.h"
#include "ipe-audit.h"

#ifdef CONFIG_SYSCTL
static int ipe_switch_mode(struct ctl_table *table, int write,
		       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int enf_old = enforce;
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (ret == 0 && enf_old != enforce)
		ipe_audit_mode_change();

	return ret;
}


static struct ctl_table_header *ipe_sysctl_header;

static int SYSCTL_ONE = 1;
static int SYSCTL_ZERO;

static const struct ctl_path ipe_sysctl_path[] = { {
							   .procname = "ipe",
						   },
						   {} };

static struct ctl_table ipe_sysctl_table[] = {
#ifndef CONFIG_SECURITY_IPE_DISABLE_AUDIT
	{
		.procname = "enforce",
		.data = &enforce,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = ipe_switch_mode,
		.extra1 = &SYSCTL_ZERO,
		.extra2 = &SYSCTL_ONE,
	},
#endif /* !CONFIG_SECURITY_IPE_DISABLE_AUDIT */
	{
		.procname = "success_audit",
		.data = &success_audit,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 = &SYSCTL_ZERO,
		.extra2 = &SYSCTL_ONE,
	},
	{}
};

static int __init ipe_sysctl_init(void)
{
	ipe_sysctl_header =
		register_sysctl_paths(ipe_sysctl_path, ipe_sysctl_table);
	if (!ipe_sysctl_header) {
		pr_err("sysctl registration failed.");
		return -ENOMEM;
	}

	return 0;
}
#else /* !CONFIG_SYSCTL */
static inline int __init ipe_sysctl_init(void)
{
	return 0;
}
#endif /* !CONFIG_SYSCTL */

static struct security_hook_list ipe_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ipe_on_exec),
	LSM_HOOK_INIT(mmap_file, ipe_on_mmap),
	LSM_HOOK_INIT(kernel_read_file, ipe_on_kernel_read),
	LSM_HOOK_INIT(kernel_load_data, ipe_on_kernel_load_data),
	LSM_HOOK_INIT(file_mprotect, ipe_on_set_executable),
	LSM_HOOK_INIT(sb_free_security, ipe_sb_free_security),
};

void __init ipe_init(void)
{
	int rc = 0;

	pr_info("IPE is currently in %s mode", enforce ? "enforce" : "audit");

	/*
	 * This failure is OK to occur. All that occurs with this failure is
	 * that sysctl can no longer be used to toggle success_audit or
	 * enforce/audit mode. The latter option is the only one that impacts
	 * any security decision, and Production systems should be using the
	 * CONFIG_SECURITY_IPE_DISABLE_AUDIT option to disable that ability
	 * anyways.
	 */
	rc = ipe_sysctl_init();
	if (rc != 0)
		pr_err("IPE failed to configure sysctl");

	security_add_hooks(ipe_hooks, ARRAY_SIZE(ipe_hooks), "IPE");
}

int enforce = 0;

#ifndef CONFIG_SECURITY_IPE_DISABLE_AUDIT

/* Module Parameter for Default Behavior on Boot */
module_param(enforce, int, 0);
MODULE_PARM_DESC(enforce, "Integrity Policy Enforcement");

#endif /* CONFIG_SECURITY_IPE_DISABLE_AUDIT */

int success_audit;

/* Module Parameter for Success Audit on Boot */
module_param(success_audit, int, 0);
MODULE_PARM_DESC(success_audit, "Integrity Policy Enforcment Successful Audit");
