// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/cls_tc.c	Netcls based traffic controller
 *
 * Authors:	Fuhai Wang <fuhaiwang@tencent.com>
 *		Zhiping Du <zhipingdu@tencent.com>
 *		Hongbo Li <herberthbli@tencent.com>
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/cls_cgroup.h>

static int cls_tc_rx(struct sock *sk, struct sk_buff *skb)
{
	struct cgroup_cls_state *cs;
	int ret = NF_ACCEPT;

	cs = sk->sk_cgrp_data.cs;
	if (!cs || !cs->classid)
		return NF_ACCEPT;

	if (sk->sk_protocol == IPPROTO_TCP) {
		/* ret = cgroup_net_rx_check(sk, skb);
		 * following patch implement this,
		 * return NF_ACCEPT or NF_DROP.
		 */
		/* for test, remove me */
		net_info_ratelimited("%s: rx pkt classid %u\n",
				     __func__, cs->classid);
	}

	return ret;
}

static unsigned int cls_tc_rx_hook(void *priv,
				  struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	struct sock *sk = skb->sk;
	int verdict;

	if (!sk ||
	    sk->sk_protocol != IPPROTO_TCP ||
	    sk->sk_state != TCP_ESTABLISHED)
		return NF_ACCEPT;

	verdict = cls_tc_rx(sk, skb);

	return verdict;
}

static struct nf_hook_ops cls_tc_hook_ops[] __read_mostly = {
	{
		.hook = cls_tc_rx_hook,
		.pf = PF_INET,
		.hooknum =  NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST,
	},
};

int cls_tc_init_module(void)
{
	int ret;

	ret = nf_register_net_hooks(&init_net, cls_tc_hook_ops,
				    ARRAY_SIZE(cls_tc_hook_ops));
	if (ret < 0)
		return ret;
	pr_info("net cls tc module init done\n");

	return 0;
}

void cls_tc_exit_module(void)
{
	nf_unregister_net_hooks(&init_net, cls_tc_hook_ops,
				ARRAY_SIZE(cls_tc_hook_ops));
	pr_info("net cls tc module exit\n");
}

module_init(cls_tc_init_module);
module_exit(cls_tc_exit_module);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Tencent OS Team <g_CAPD_SRDC_OS@tencent.com>");
MODULE_DESCRIPTION("Tencent traffic control based on cgroup net classid.");

