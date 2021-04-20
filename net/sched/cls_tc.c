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
#include <net/tcp.h>
#include <net/cls_cgroup.h>

int sysctl_net_isolation_enable __read_mostly;
struct ctl_table_header *net_isolation_sysctl_header;

static int cls_tc_rx(struct sock *sk, struct sk_buff *skb)
{
	struct cgroup_cls_state *cs;
	int ret = NF_ACCEPT;

	cs = sk->sk_cgrp_data.cs;
	if (!cs)
		return NF_ACCEPT;

	if (sk->sk_protocol == IPPROTO_TCP) {
		struct tcphdr *th = tcp_hdr(skb);

		if (th->syn || th->rst || th->fin)
			return NF_ACCEPT;
		/* ret = cgroup_net_rx_check(sk, skb);
		 * following patch implement this,
		 * return NF_ACCEPT or NF_DROP.
		 */
		ret = cls_cgroup_rx_accept(sk, skb);
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

	if (!sk->in_dev)
		sk->in_dev = skb->in_dev;

	verdict = cls_tc_rx(sk, skb);

	return verdict;
}

static int cls_tc_tx(struct sock *sk, struct sk_buff *skb)
{
	struct cgroup_cls_state *cs;
	int ret = NF_ACCEPT;

	cs = sk->sk_cgrp_data.cs;
	if (!cs)
		return NF_ACCEPT;

	if (sk->sk_protocol == IPPROTO_TCP) {
		struct tcphdr *th = tcp_hdr(skb);

		if (th->syn || th->rst || th->fin)
			return NF_ACCEPT;

		ret = cls_cgroup_tx_accept(sk, skb);
	}

	return ret;
}

static unsigned int cls_tc_tx_hook(void *priv,
				   struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	struct sock *sk = skb->sk;
	int verdict;

	if (!sysctl_net_isolation_enable)
		return NF_ACCEPT;

	if (!sk ||
	    sk->sk_protocol != IPPROTO_TCP ||
	    sk->sk_state != TCP_ESTABLISHED)
		return NF_ACCEPT;

	verdict = cls_tc_tx(sk, skb);
	//if (verdict == NF_DROP)
	//      tcp_enter_cwr(sk, 1);

	return verdict;
}

static struct nf_hook_ops cls_tc_hook_ops[] __read_mostly = {
	{
		.hook = cls_tc_rx_hook,
		.pf = PF_INET,
		.hooknum =  NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = cls_tc_tx_hook,
		.pf = PF_INET,
		.hooknum =  NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST,
	},
};

static struct ctl_table net_isolation_table[] = {
	{
		.procname	= "net_isolation",
		.data		= &sysctl_net_isolation_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{}
};

int cls_tc_init_module(void)
{
	int ret;

	ret = nf_register_net_hooks(&init_net, cls_tc_hook_ops,
				    ARRAY_SIZE(cls_tc_hook_ops));
	if (ret < 0)
		return ret;

	net_isolation_sysctl_header = register_net_sysctl(&init_net,
					"net/core", net_isolation_table);
	if (!net_isolation_sysctl_header) {
		pr_info(KERN_ERR "net cls tc module init register sysctl error\n");
		return -EINVAL;
	}
	pr_info(KERN_INFO "net cls tc module init done\n");

	return 0;
}

static int __init net_isolate_setup(char *str)
{
	sysctl_net_isolation_enable = 1;
	return 1;
}
__setup("net_isolation", net_isolate_setup);

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

