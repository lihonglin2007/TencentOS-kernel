/*
 * net/sched/rx_cgroup.c receive side cgroup
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/cgroup.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include "rx_cgroup.h"


#define BASE_DEPTH              (640 * 1024)

/* 1000 * 1M = 1Gbps */
static u64 rx_rate_max = 1000;
static u64 rx_rate_min;
static int rx_min_rwnd_segs = 2;

static struct rx_token_bucket token_pool_hi;
static struct rx_token_bucket token_pool_lo;
static DEFINE_MUTEX(config_lock);


static void align_to_depth(struct rx_token_bucket *tb)
{
	if (atomic64_read(&tb->tokens) > tb->depth)
		atomic64_set(&tb->tokens, tb->depth);
	if (atomic64_read(&tb->tokens) < -tb->depth)
		atomic64_set(&tb->tokens, -tb->depth);
}

static int tb_set_depth(struct rx_token_bucket *tb, s64 depth)
{
	if (depth < 0)
		return -EINVAL;

	tb->depth = depth;
	tb->max_ticks = bytes_to_ns(tb->rate, depth);

	if (tb->rate > 1)
		tb->max_ticks = min(tb->max_ticks, (s64)(ULONG_MAX / tb->rate));

	return 0;
}

static u32 calibrate_depth(u64 rate)
{
	unsigned long factor;

	if (!rate)
		return 0;
	factor = rate / (NET_MSCALE >> 3);

	return BASE_DEPTH * int_sqrt(factor);
}

static int rx_tb_set_rate(struct rx_token_bucket *tb, u64 rate)
{
	s64 depth;

	tb->rate = (rate * NET_MSCALE) >> 3;
	depth = calibrate_depth(tb->rate);
	tb_set_depth(tb, depth);
	align_to_depth(tb);
	atomic64_set(&tb->t_c, ktime_to_ns(ktime_get()));
	tb->wnd_scale = WND_DIVISOR;
	return 0;
}

static void dump_tb(struct cgroup_subsys_state *css, struct seq_file *sf,
		    struct rx_token_bucket *tb)
{
	seq_printf(sf, "rx rate(Mbps)\t: %llu\n", (tb->rate << 3) / NET_MSCALE);
	seq_printf(sf, "depth(Bytes)\t: %lld\n", tb->depth);
	seq_printf(sf, "max_ticks(ns)\t: %lld\n", tb->max_ticks);
	seq_printf(sf, "tokens(Bytes)\t: %ld/%lld\n",
			atomic64_read(&tb->tokens), tb->depth);
	seq_printf(sf, "wnd_scale\t: %d\n", tb->wnd_scale);
}

int read_sys_tb(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);

	dump_tb(css, sf, &token_pool_hi);
	dump_tb(css, sf, &token_pool_lo);
	return 0;
}

void rx_cgroup_tb_init(struct cgroup_subsys_state *css)
{
	rx_tb_set_rate(&token_pool_lo, rx_rate_min);
	rx_tb_set_rate(&token_pool_hi, rx_rate_max - rx_rate_min);
}

int read_rx_stat(struct cgroup_subsys_state *css, struct seq_file *sf)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct gnet_stats_basic_packed *bstats =  &cs->rx_stats.bstats;
	struct net_rate_estimator *est =  cs->rx_stats.est;
	struct gnet_stats_rate_est64 sample;
	bool success = gen_estimator_read(&cs->rx_stats.est, &sample);
	u64 rate;

	if (!success)
		return -1;
	spin_lock(&cs->rx_stats.lock);
	rate = ((u64)sample.bps << 3) / NET_MSCALE;
	seq_printf(sf, "rx packets\t: %u\n", bstats->packets);
	seq_printf(sf, "rx bytes\t: %llu\n", bstats->bytes);
	seq_printf(sf, "rx pkts/s\t: %llu\n", sample.pps);
	seq_printf(sf, "rx rate(Mbit/s)\t: %llu\n", rate);
	seq_printf(sf, "prio:\t\t: %d\n", cs->prio);
	spin_unlock(&cs->rx_stats.lock);

	seq_printf(sf, "rx drop\t\t: %ld\n",
			atomic64_read(&cs->rx_stats.dropped));

	return 0;
}

u64 read_rx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return rx_rate_max;
}

int write_rx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft, u64 value)
{
	mutex_lock(&config_lock);
	if (value < rx_rate_min) {
		mutex_unlock(&config_lock);
		return -EINVAL;
	}

	if (value != rx_rate_max) {
		rx_rate_max = value;
		rx_tb_set_rate(&token_pool_hi, rx_rate_max - rx_rate_min);
		rx_tb_set_rate(&token_pool_lo, rx_rate_min);
	}
	mutex_unlock(&config_lock);
	return 0;
}

u64 read_rx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return rx_rate_min;
}

int write_rx_min_rwnd_segs(struct cgroup_subsys_state *css, struct cftype *cft, u64 value)
{
	rx_min_rwnd_segs = (u32)value;
	return 0;
}

u64 read_rx_min_rwnd_segs(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return (u64)rx_min_rwnd_segs;
}


int write_rx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft, u64 value)
{
	mutex_lock(&config_lock);
	if (value > rx_rate_max) {
		mutex_unlock(&config_lock);
		return -EINVAL;
	}
	if (value != rx_rate_min) {
		rx_rate_min = value;
		rx_tb_set_rate(&token_pool_hi, rx_rate_max - rx_rate_min);
		rx_tb_set_rate(&token_pool_lo, rx_rate_min);
	}
	mutex_unlock(&config_lock);

	return 0;
}

static inline long rx_charge_token(struct rx_token_bucket *tb, s64 now)
{
	s64 old, res, diff;

	old = atomic64_read(&tb->t_c);
	if (now - old > tb->max_ticks >> TOKEN_CHARGE_TIKES) {
		res = atomic64_cmpxchg(&tb->t_c, old, now);
		if (res == old) {
			diff = min_t(s64, now - old, tb->max_ticks);
			atomic64_add(ns_to_bytes(tb->rate, diff), &tb->tokens);
			align_to_depth(tb);
		}
	}
	return atomic64_read(&tb->tokens);
}

static void update_wnd_factor(struct cgroup_cls_state *cs)
{
	struct rx_token_bucket *tb = &token_pool_lo;
	s64 tokens, depth;
	int scale = 0;

	depth = tb->depth;
	tokens = atomic64_read(&tb->tokens);
	if (tokens >= 0 || !depth)
		scale = WND_DIVISOR;
	else
		scale = WND_DIVISOR + tokens * WND_DIVISOR / depth;

	tb->wnd_scale = scale;
}

static bool rx_cgroup_throttle(struct cgroup_cls_state *cs,
		int prio, struct sk_buff *skb)
{
	struct rx_token_bucket *tb_hi = &token_pool_hi;
	struct rx_token_bucket *tb_lo = &token_pool_lo;
	s64 now;
	int len;
	s64 hi_tokens, lo_tokens;
	bool accept = true;

	len = skb->len;
	if (len > tb_lo->depth)
		return true;

	now = ktime_to_ns(ktime_get());
	lo_tokens = rx_charge_token(tb_lo, now);
	hi_tokens = rx_charge_token(tb_hi, now);

	if (prio == CLS_TC_PRIO_HIGH) {
		if (tb_hi->rate == RATE_UNLIMITED)
			goto out;

		if (lo_tokens > len) {
			atomic64_sub(len, &tb_lo->tokens);
			goto out;
		}

		if (hi_tokens > len) {
			atomic64_sub(len, &tb_hi->tokens);
			goto out;
		}

		atomic64_sub(min(hi_tokens + tb_hi->depth, (s64)len),
			    &tb_hi->tokens);
	} else {
		if (tb_lo->rate == RATE_UNLIMITED)
			goto out;


		if (hi_tokens > len + tb_hi->depth / 2) {
			atomic64_sub(len, &tb_hi->tokens);
			goto out;
		}

		if (atomic64_read(&tb_lo->tokens) + tb_lo->depth > len) {
			atomic64_sub(len, &tb_lo->tokens);
			goto out;
		}
		accept = false;
	}
out:
	update_wnd_factor(cs);
	return accept;
}

u32 cls_cgroup_adjust_wnd(struct sock *sk, u32 wnd, u32 mss, u16 wscale)
{
	struct cgroup_cls_state *cs = sk->sk_cgrp_data.cs;
	struct rx_token_bucket *tb = &token_pool_lo;
	u32 new_wnd;
	u64 high_wnd;
	int sysctl_tcp_rmem2 = sock_net(sk)->ipv4.sysctl_tcp_rmem[2];
	int scale = tb->wnd_scale;

	if (!wnd || !cs || !mss || cs->prio == CLS_TC_PRIO_HIGH)
		return wnd;

	high_wnd = ((u64)sysctl_tcp_rmem2 * scale * scale) >> (WND_DIV_SHIFT * 2);
	new_wnd = min((u64)wnd, high_wnd);
	new_wnd = max(new_wnd, rx_min_rwnd_segs * mss);
	new_wnd = ALIGN(new_wnd, 1 << wscale);
	new_wnd = min(new_wnd, wnd);

	return new_wnd;
}

bool cls_cgroup_rx_accept(struct sock *sk, struct sk_buff *skb)
{
	struct cgroup_cls_state *cs = sk->sk_cgrp_data.cs;
	struct net_device *dev = skb->dev;
	bool accept = true;

	if (!cs)
		return true;

	if (!tc_dev || tc_dev != sk->in_dev)
		return true;

	accept = rx_cgroup_throttle(cs, cs->prio, skb);
	if (!accept) {
		atomic64_inc(&cs->rx_stats.dropped);
		return accept;
	}
	cs->rx_stats.bstats.packets++;
	cs->rx_stats.bstats.bytes += skb->len;

	return accept;
}

int cls_cgroup_factor(const struct sock *sk)
{
	struct rx_token_bucket *tb = &token_pool_lo;
	struct cgroup_cls_state *cs = sk->sk_cgrp_data.cs;

	if (!cs || cs->prio == CLS_TC_PRIO_HIGH)
		return WND_DIVISOR;

	return max(tb->wnd_scale, (u16)1);
}

bool is_low_prio(struct sock *sk)
{
	struct cgroup_cls_state *cs = sk->sk_cgrp_data.cs;

	if (!cs)
		return false;

	return cs->prio == CLS_TC_PRIO_NORMAL;
}
