#include "core.h"

#include "common.h"
#include "log.h"
#include "4to6.h"
#include "6to4.h"

static const struct translation_steps steps64 = {
	.pkt_init = pkt_init_ipv6,
	.skb_alloc = ttp64_alloc_skb,
	.xlat_l3 = ttp64_ipv4_external,
	.xlat_tcp = ttp64_tcp,
	.xlat_udp = ttp64_udp,
	.xlat_icmp = ttp64_icmp,
};

static const struct translation_steps steps46 = {
	.pkt_init = pkt_init_ipv4,
	.skb_alloc = ttp46_alloc_skb,
	.xlat_l3 = ttp46_ipv6_external,
	.xlat_tcp = ttp46_tcp,
	.xlat_udp = ttp46_udp,
	.xlat_icmp = ttp46_icmp,
};

static bool has_l4_hdr(struct xlation *state)
{
	switch (state->in.l3_proto) {
	case PF_INET6:
		return is_first_frag6(pkt_frag_hdr(&state->in));
	case PF_INET:
		return is_first_frag4(pkt_ip4_hdr(&state->in));
	}

	WARN(1, "Supposedly unreachable code reached. Proto: %u",
	     state->in.l3_proto);
	return false;
}

void jool_xlat(struct xlation *state, struct sk_buff *in)
{
	struct translation_steps const *steps;

	state->stats->rx_packets++;
	state->stats->rx_bytes += in->len;

	switch (ntohs(in->protocol)) {
	case ETH_P_IPV6:
		steps = &steps64;
		break;
	case ETH_P_IP:
		steps = &steps46;
		break;
	default:
		log_debug("Unknown l3 proto: %u", ntohs(in->protocol));
		drop(state);
		return;
	}

	if (steps->pkt_init(state, in) != 0)
		return;
	if (steps->skb_alloc(state) != 0)
		return;
	if (steps->xlat_l3(state) != 0)
		goto revert;
	if (has_l4_hdr(state) && (xlat_l4_function(state, steps) != 0))
		goto revert;
	return;

revert:
	kfree_skb_list(state->out.skb);
	state->out.skb = NULL;
}
