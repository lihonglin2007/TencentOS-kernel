/*
 * cls_cgroup.h			Control Group Classifier
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef _NET_CLS_CGROUP_H
#define _NET_CLS_CGROUP_H

#include <linux/cgroup.h>
#include <linux/hardirq.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/gen_stats.h>
#include <linux/pkt_sched.h>

#ifdef CONFIG_CGROUP_NET_CLASSID

#define NET_MSCALE          (1000 * 1000)
#define RATE_UNLIMITED      0
#define TOKEN_CHARGE_TIKES  16
#define WND_DIV_SHIFT       10
#define WND_DIVISOR         (1 << WND_DIV_SHIFT)

enum {
	CLS_TC_RX,
	CLS_TC_TX,
	CLS_TC_DIRECTION_MAX
};

enum {
	CLS_TC_PRIO_HIGH,
	CLS_TC_PRIO_NORMAL,
	CLS_TC_PRIO_MAX
};

struct cls_cgroup_stats {
	struct gnet_stats_basic_packed bstats;
	struct net_rate_estimator __rcu *est;
	spinlock_t lock;
	atomic64_t dropped;
};

struct cgroup_cls_state {
	struct cgroup_subsys_state css;
	struct cls_cgroup_stats rx_stats;
	struct cls_cgroup_stats tx_stats;
	u32 classid;
	u32 prio;
};

static inline struct cgroup_cls_state *css_cls_state(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cgroup_cls_state, css) : NULL;
}

struct cgroup_cls_state *task_cls_state(struct task_struct *p);

static inline u32 task_cls_classid(struct task_struct *p)
{
	u32 classid;

	if (in_interrupt())
		return 0;

	rcu_read_lock();
	classid = container_of(task_css(p, net_cls_cgrp_id),
			       struct cgroup_cls_state, css)->classid;
	rcu_read_unlock();

	return classid;
}

static inline void sock_update_classid(struct sock_cgroup_data *skcd)
{
	u32 classid;

	classid = task_cls_classid(current);
	sock_cgroup_set_classid(skcd, classid);
	skcd->cs = task_cls_state(current);
}

static inline u32 task_get_classid(const struct sk_buff *skb)
{
	u32 classid = task_cls_state(current)->classid;

	/* Due to the nature of the classifier it is required to ignore all
	 * packets originating from softirq context as accessing `current'
	 * would lead to false results.
	 *
	 * This test assumes that all callers of dev_queue_xmit() explicitly
	 * disable bh. Knowing this, it is possible to detect softirq based
	 * calls by looking at the number of nested bh disable calls because
	 * softirqs always disables bh.
	 */
	if (in_serving_softirq()) {
		struct sock *sk = skb_to_full_sk(skb);

		/* If there is an sock_cgroup_classid we'll use that. */
		if (!sk || !sk_fullsock(sk))
			return 0;

		classid = sock_cgroup_classid(&sk->sk_cgrp_data);
	}

	return classid;
}

static inline s64 ns_to_bytes(u64 rate, s64 diff)
{
	return rate * (u64)diff / NSEC_PER_SEC;
}

static inline s64 bytes_to_ns(u64 rate, u64 bytes)
{
	if (unlikely(!rate))
		return 0;

	return bytes * NSEC_PER_SEC / rate;
}

extern inline struct cgroup_cls_state *cgrp_cls_state(struct cgroup *cgrp);
extern void sock_update_classid(struct sock_cgroup_data *skcd);
extern bool cls_cgroup_rx_accept(struct sock *sk, struct sk_buff *skb);
extern bool cls_cgroup_tx_accept(struct sock *sk, struct sk_buff *skb);
extern u32 cls_cgroup_adjust_wnd(struct sock *sk, u32 wnd, u32 mss, u16 wscale);
extern int cls_cgroup_factor(const struct sock *sk);
extern bool is_low_prio(struct sock *sk);
extern char tc_dev_name[IFNAMSIZ];
extern struct net_device *tc_dev;
extern int sysctl_net_isolation_enable;

#else /* !CONFIG_CGROUP_NET_CLASSID */
static inline void sock_update_classid(struct sock_cgroup_data *skcd)
{
}

static inline u32 task_get_classid(const struct sk_buff *skb)
{
	return 0;
}
#endif /* CONFIG_CGROUP_NET_CLASSID */
#endif  /* _NET_CLS_CGROUP_H */
