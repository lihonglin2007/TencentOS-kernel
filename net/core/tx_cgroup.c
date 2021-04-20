/*
 * net/sched/tx_cgroup.c tx side cgroup
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
#include "tx_cgroup.h"


/* max accumulation time defalut 0s */
#define TX_BUFFER_TIME_MAX	1ULL

/* 1000 * 1M = 1Gbps */
static u64 tx_rate_max = 1000;
static u64 tx_rate_min;

static struct tx_token_bucket token_pool_hi;
static struct tx_token_bucket token_pool_lo;
static DEFINE_MUTEX(config_lock);


static void align_to_depth(struct tx_token_bucket *tb)
{
	if (atomic64_read(&tb->tokens) > tb->depth)
		atomic64_set(&tb->tokens, tb->depth);

	if (atomic64_read(&tb->tokens) < -tb->depth)
		atomic64_set(&tb->tokens, -tb->depth);
}

static int tx_tb_set_rate(struct tx_token_bucket *tb, u64 rate)
{
	tb->rate = (rate * NET_MSCALE) >> 3;
	tb->depth = TX_BUFFER_TIME_MAX * tb->rate;
	tb->max_ticks = TX_BUFFER_TIME_MAX * NSEC_PER_SEC;
	align_to_depth(tb);
	atomic64_set(&tb->t_c, ktime_to_ns(ktime_get()));

	return 0;
}

void tx_cgroup_tb_init(struct cgroup_subsys_state *css)
{
	tx_tb_set_rate(&token_pool_lo, tx_rate_min);
	tx_tb_set_rate(&token_pool_hi, tx_rate_max - tx_rate_min);
}
int read_tx_stat(struct cgroup_subsys_state *css, struct seq_file *sf)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct gnet_stats_basic_packed *bstats =  &cs->tx_stats.bstats;
	struct net_rate_estimator *est =  cs->tx_stats.est;
	struct gnet_stats_rate_est64 sample;
	bool success = gen_estimator_read(&cs->tx_stats.est, &sample);
	u64 rate;

	if (!success)
		return -1;

	spin_lock(&cs->tx_stats.lock);
	rate = ((u64)sample.bps << 3)/NET_MSCALE;
	seq_printf(sf, "tx packets\t: %u\n", bstats->packets);
	seq_printf(sf, "tx bytes\t: %llu\n", bstats->bytes);
	seq_printf(sf, "tx pkts/s\t: %u\n", sample.pps);
	seq_printf(sf, "tx rate(Mbit/s)\t: %llu\n", rate);
	spin_unlock(&cs->tx_stats.lock);

	seq_printf(sf, "tx drop\t\t: %ld\n",
			atomic64_read(&cs->tx_stats.dropped));

	return 0;
}

u64 read_tx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return tx_rate_max;
}

int write_tx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft, u64 value)
{
	mutex_lock(&config_lock);
	if (value < tx_rate_min) {
		mutex_unlock(&config_lock);
		return -EINVAL;
	}
	if (value != tx_rate_max) {
		tx_rate_max = value;
		tx_tb_set_rate(&token_pool_hi, tx_rate_max - tx_rate_min);
		tx_tb_set_rate(&token_pool_lo, tx_rate_min);
	}
	mutex_unlock(&config_lock);
	return 0;
}

u64 read_tx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return tx_rate_min;
}

int write_tx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft, u64 value)
{
	mutex_lock(&config_lock);
	if (value > tx_rate_max) {
		mutex_unlock(&config_lock);
		return -EINVAL;
	}
	if (value != tx_rate_min) {
		tx_rate_min = value;
		tx_tb_set_rate(&token_pool_hi, tx_rate_max - tx_rate_min);
		tx_tb_set_rate(&token_pool_lo, tx_rate_min);
	}
	mutex_unlock(&config_lock);
	return 0;
}

static inline long tx_charge_token(struct tx_token_bucket *tb, s64 now)
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

static bool tx_cgroup_throttle(struct cgroup_cls_state *cs,
		    int prio, struct sk_buff *skb)
{
	struct tx_token_bucket *tb_hi = &token_pool_hi;
	struct tx_token_bucket *tb_lo = &token_pool_lo;
	s64 now;
	s64 hi_tokens, lo_tokens;
	bool accept = true;
	int len;

	len = skb->len;
	if (len > tb_lo->depth)
		return true;

	now = ktime_to_ns(ktime_get());
	if (prio == CLS_TC_PRIO_HIGH) {
		if (tb_hi->rate == RATE_UNLIMITED)
			return true;
		lo_tokens = tx_charge_token(tb_lo, now);
		if (lo_tokens > len) {
			atomic64_sub(len, &tb_lo->tokens);
			return true;
		}

		hi_tokens = tx_charge_token(tb_hi, now);
		if (hi_tokens > len) {
			atomic64_sub(len, &tb_hi->tokens);
			return true;
		}

		atomic64_sub(min(hi_tokens + tb_hi->depth, (s64)len),
				&tb_hi->tokens);
	} else {
		if (tb_lo->rate == RATE_UNLIMITED)
			return true;
		hi_tokens = tx_charge_token(tb_hi, now);
		lo_tokens = tx_charge_token(tb_lo, now);
		if (hi_tokens > len) {
			atomic64_sub(len, &tb_hi->tokens);
			return true;
		}

		if (atomic64_read(&tb_lo->tokens) + tb_lo->depth > len) {
			atomic64_sub(len, &tb_lo->tokens);
			return true;
		}
		accept = false;
	}
	return accept;
}

bool cls_cgroup_tx_accept(struct sock *sk, struct sk_buff *skb)
{
	struct cgroup_cls_state *cs = sk->sk_cgrp_data.cs;
	bool accept = true;

	if (!cs)
		return true;

	if (!tc_dev || tc_dev != sk->in_dev)
		return true;

	accept = tx_cgroup_throttle(cs, cs->prio, skb);
	if (!accept) {
		atomic64_inc(&cs->tx_stats.dropped);
		return accept;
	}
	cs->tx_stats.bstats.packets++;
	cs->tx_stats.bstats.bytes += skb->len;
	return accept;
}
