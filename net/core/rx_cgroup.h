#ifndef _NET_RX_CGROUP_H
#define _NET_RX_CGROUP_H
#include <linux/types.h>
#include <linux/kernel.h>
#include <net/pkt_sched.h>
#include <net/cls_cgroup.h>
#include <linux/skbuff.h>
#include <linux/seq_file.h>

struct rx_token_bucket {
	s64 depth;		/* depth in bytes. */
	s64 max_ticks;		/* bound of time diff. */
	atomic64_t tokens;	/* number of tokens in bytes. */
	atomic64_t t_c;		/* last time we touch it. */
	u64 rate;		/* rate of token generation. */
	u16 wnd_scale;
};

int read_rx_stat(struct cgroup_subsys_state *css, struct seq_file *sf);
u64 read_rx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft);
int write_rx_bw_max(struct cgroup_subsys_state *css, struct cftype *cft, u64 value);
u64 read_rx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft);
int write_rx_bw_min(struct cgroup_subsys_state *css, struct cftype *cft, u64 value);
int read_class_stat(struct seq_file *sf, void *v);
int read_sys_tb(struct seq_file *sf, void *v);

void rx_cgroup_tb_init(struct cgroup_subsys_state *css);

int write_rx_min_rwnd_segs(struct cgroup_subsys_state *css, struct cftype *cft, u64 value);
u64 read_rx_min_rwnd_segs(struct cgroup_subsys_state *css, struct cftype *cft);
bool cls_cgroup_rx_accept(struct sock *sk, struct sk_buff *skb);

#endif	/* _NET_RX_CGROUP_H */
