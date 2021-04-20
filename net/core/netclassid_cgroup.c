/*
 * net/core/netclassid_cgroup.c	Classid Cgroupfs Handling
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fdtable.h>
#include <linux/sched/task.h>

#include <net/cls_cgroup.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/string.h>
#include "tx_cgroup.h"
#include "rx_cgroup.h"

char tc_dev_name[IFNAMSIZ];
struct net_device  *tc_dev;

struct cgroup_cls_state *task_cls_state(struct task_struct *p)
{
	return css_cls_state(task_css_check(p, net_cls_cgrp_id,
					    rcu_read_lock_bh_held()));
}
EXPORT_SYMBOL_GPL(task_cls_state);

int cls_cgroup_stats_init(struct cls_cgroup_stats *stats)
{
	struct {
		struct nlattr nla;
		struct gnet_estimator params;
	} opt;
	int err;

	opt.nla.nla_len = nla_attr_size(sizeof(opt.params));
	opt.nla.nla_type = TCA_RATE;
	opt.params.interval = 0; /* statistics every 1s. */
	opt.params.ewma_log = 0; /* ewma off. */
	spin_lock_init(&stats->lock);

	rtnl_lock();
	err = gen_new_estimator(&stats->bstats,
				NULL,
				&stats->est,
				&stats->lock,
				NULL,
				&opt.nla);

	if (err)
		pr_err("gen_new_estimator failed(%d)\n", err);
	rtnl_unlock();

	return err;
}

void cls_cgroup_stats_destroy(struct cls_cgroup_stats *stats)
{
	rtnl_lock();
	gen_kill_estimator(&stats->est);
	rtnl_unlock();
}

static struct cgroup_subsys_state *
cgrp_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cgroup_cls_state *cs;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return ERR_PTR(-ENOMEM);

	return &cs->css;
}

static int cgrp_css_online(struct cgroup_subsys_state *css)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct cgroup_cls_state *parent = css_cls_state(css->parent);

	if (!parent) {
		rx_cgroup_tb_init(css);
		tx_cgroup_tb_init(css);
	}

	if (parent) {
		cs->prio = parent->prio;
		cs->classid = parent->classid;
	}

	cls_cgroup_stats_init(&cs->rx_stats);
	cls_cgroup_stats_init(&cs->tx_stats);
	return 0;
}

static void cgrp_css_offline(struct cgroup_subsys_state *css)
{
	struct cgroup_cls_state *cs = css_cls_state(css);

	cls_cgroup_stats_destroy(&cs->rx_stats);
	cls_cgroup_stats_destroy(&cs->tx_stats);
}

static void cgrp_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_cls_state(css));
}

struct update_classid_context {
	u32 classid;
	struct task_struct *task;
};

static int update_classid_sock(const void *v, struct file *file, unsigned n)
{
	int err;
	struct update_classid_context *ctx = (void *)v;
	struct socket *sock = sock_from_file(file, &err);

	if (sock) {
		spin_lock(&cgroup_sk_update_lock);
		sock_cgroup_set_classid(&sock->sk->sk_cgrp_data, ctx->classid);
		sock->sk->sk_cgrp_data.cs = task_cls_state(ctx->task);
		spin_unlock(&cgroup_sk_update_lock);
	}
	return 0;
}

static void update_classid_task(struct task_struct *p, u32 classid)
{
	struct update_classid_context ctx = {
		.classid = classid,
		.task = p
	};
	unsigned int fd = 0;

	do {
		task_lock(p);
		fd = iterate_fd(p->files, fd, update_classid_sock, &ctx);
		task_unlock(p);
		cond_resched();
	} while (fd);
}

static void cgrp_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *p;

	cgroup_taskset_for_each(p, css, tset) {
		update_classid_task(p, css_cls_state(css)->classid);
	}
}

static u64 read_classid(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->classid;
}

static int write_classid(struct cgroup_subsys_state *css, struct cftype *cft,
			 u64 value)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct css_task_iter it;
	struct task_struct *p;

	cgroup_sk_alloc_disable();

	cs->classid = (u32)value;

	css_task_iter_start(css, 0, &it);
	while ((p = css_task_iter_next(&it))) {
		task_lock(p);
		iterate_fd(p->files, 0, update_classid_sock,
			   (void *)(unsigned long)cs->classid);
		task_unlock(p);
		cond_resched();
	}
	css_task_iter_end(&it);

	return 0;
}

static u64 read_class_prio(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->prio;
}

static int write_class_prio(struct cgroup_subsys_state *css, struct cftype *cft,
			 u64 value)
{
	if (value >= CLS_TC_PRIO_MAX)
		return -EINVAL;

	css_cls_state(css)->prio = (u32) value;

	return 0;
}

static ssize_t write_dev_name(struct kernfs_open_file *of,
			    char *buf, size_t nbytes, loff_t off)
{
	struct net_device *dev;
	struct net *net = current->nsproxy->net_ns;

	buf = strim(buf);
	if (!strcmp(tc_dev_name, buf))
		return nbytes;

	dev = dev_get_by_name(net, buf);
	if (!dev) {
		pr_err("Netdev name %s not found!\n", buf);
		return -ENODEV;
	}
	strncpy(tc_dev_name, buf, IFNAMSIZ);
	tc_dev = dev;
	dev_put(dev);

	return nbytes;
}

static int read_dev_name(struct seq_file *sf, void *v)
{
	seq_printf(sf, "%s\n", tc_dev_name);
	return 0;
}

int read_class_stat(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);

	read_tx_stat(css, sf);
	read_rx_stat(css, sf);
	return 0;
}

static struct cftype ss_files[] = {
	{
		.name		= "classid",
		.read_u64	= read_classid,
		.write_u64	= write_classid,
	},
	{
		.name		= "dev_name",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.seq_show	= read_dev_name,
		.write		= write_dev_name,
	},
	{
		.name		= "tx_bw_min",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.read_u64	= read_tx_bw_min,
		.write_u64	= write_tx_bw_min,
	},
	{
		.name		= "tx_bw_max",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.read_u64	= read_tx_bw_max,
		.write_u64	= write_tx_bw_max,
	},
	{
		.name		= "rx_bw_max",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.read_u64	= read_rx_bw_max,
		.write_u64	= write_rx_bw_max,
	},
	{
		.name		= "rx_bw_min",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.read_u64	= read_rx_bw_min,
		.write_u64	= write_rx_bw_min,
	},
	{
		.name		= "rx_min_rwnd_segs",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.read_u64	= read_rx_min_rwnd_segs,
		.write_u64	= write_rx_min_rwnd_segs,
	},
	{
		.name		= "stat",
		.seq_show	= read_class_stat,
	},
	{
		.name		= "prio",
		.read_u64	= read_class_prio,
		.write_u64	= write_class_prio,
	},
	{
		.name		= "dump",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.seq_show	= read_sys_tb,
	},
	{ }	/* terminate */
};

struct cgroup_subsys net_cls_cgrp_subsys = {
	.css_alloc		= cgrp_css_alloc,
	.css_online		= cgrp_css_online,
	.css_offline		= cgrp_css_offline,
	.css_free		= cgrp_css_free,
	.attach			= cgrp_attach,
	.legacy_cftypes		= ss_files,
};

static int __init net_isolate_setup(char *str)
{
	sysctl_net_isolation_enable = 1;
	return 1;
}
__setup("net_isolate", net_isolate_setup);

