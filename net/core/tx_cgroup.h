#ifndef _NET_TX_CGROUP_H
#define _NET_TX_CGROUP_H
#include <linux/types.h>
#include <linux/kernel.h>
#include <net/pkt_sched.h>
#include <net/cls_cgroup.h>
#include <linux/skbuff.h>
#include <linux/seq_file.h>

struct tx_token_bucket {
	s64 depth;		/* depth in bytes. */
	s64 max_ticks;		/* bound of time diff. */
	atomic64_t tokens;	/* number of tokens in bytes. */
	atomic64_t t_c;		/* last time we touch it. */
	u64 rate;		/* rate of token generation. */
};

int read_tx_stat(struct cgroup_subsys_state *css, struct seq_file *sf);
u64 read_tx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft);
int write_tx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft, u64 value);
u64 read_tx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft);
int write_tx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft, u64 value);
void tx_cgroup_tb_init(struct cgroup_subsys_state *css);
bool cls_cgroup_tx_accept(struct sock *sk, struct sk_buff *skb);

#endif	/* _NET_TX_CGROUP_H */
