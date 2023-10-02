#include "4to6.h"

#include <net/addrconf.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/ip6_checksum.h>

#include "address.h"
#include "common.h"
#include "log.h"
#include "translation_state.h"

/* Code 0 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_PTR_INDICATES_ERROR 0
/* Code 2 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_BAD_LENGTH 2

/* Layer 3 only */
#define HDRS_LEN (sizeof(struct ipv6hdr) + sizeof(struct frag_hdr))

static __u8 proto2nexthdr(__u8 protocol)
{
	return (protocol == IPPROTO_ICMP) ? NEXTHDR_ICMP : protocol;
}

static int iphdr_delta(struct iphdr *hdr4)
{
	return sizeof(struct ipv6hdr) - (hdr4->ihl << 2);
}

/*
 * Returns the "ideal" (ie. Fast Path only) allocation difference between
 * in->skb and out->skb.
 *
 * Please note that there is no guarantee that delta will be positive. If the
 * IPv4 header has lots of options, it might exceed the IPv6 header length.
 */
static int get_delta(struct packet *in)
{
	struct iphdr *hdr4;
	int delta;

	/*
	 * The following is assumed by this code:
	 *
	 * The IPv4 header will be replaced by a IPv6 header and possibly a
	 * fragment header.
	 * The L4 header will never change in size.
	 *    (In particular, ICMPv4 hdr len == ICMPv6 hdr len)
	 * The payload will not change in TCP, UDP and ICMP infos.
	 *
	 * As for ICMP errors:
	 * The sub-IPv4 header will be replaced by an IPv6 header and possibly a
	 * fragment header.
	 * The sub-L4 header will never change in size.
	 * The subpayload will never change in size (for now).
	 */

	hdr4 = pkt_ip4_hdr(in);
	delta = iphdr_delta(hdr4) + sizeof(struct frag_hdr);

	if (pkt_is_icmp4_error(in)) {
		hdr4 = pkt_payload(in);
		delta += iphdr_delta(hdr4);
		if (will_need_frag_hdr(hdr4))
			delta += sizeof(struct frag_hdr);
	}

	return delta;
}

static unsigned int fragment_exceeds_mtu46(struct packet *in)
{
	struct skb_shared_info *shinfo;
	unsigned int headers;
	unsigned int payload;

	/*
	 * Damn it. Should I worry about frag_list before or after GRO?
	 *
	 * My gut says it doesn't make sense for frag_list packets to contain
	 * GRO data, because if the GRO was TCP, then how would it have
	 * unsegmented (L4) data that hasn't been defragmented (L3) yet? And UFO
	 * already defragments, so why would nf_defrag_ipv4 kick in?
	 *
	 * On the other hand, I think I *have* seen populated frags in
	 * frag_list. But that's not necessarily GRO's doing. Maybe the NIC
	 * simply allocated small buffers for a single packet. I don't think I
	 * queried gso_size that time.
	 *
	 * Bleargh.
	 */

	shinfo = skb_shinfo(in->skb);
	if (shinfo->gso_size) {
		payload = shinfo->gso_size;
		goto include_headers;
	}

	if (shinfo->frag_list) {
		/*
		 * Note: From context, we know DF is enabled.
		 * nf_defrag_ipv4 only enables DF when the biggest DF fragment
		 * is also the biggest fragment.
		 */
		return IPCB(in->skb)->frag_max_size;
	}

	payload = in->skb->len - pkt_hdrs_len(in);
	/* Fall through */

include_headers:
	headers = sizeof(struct ipv6hdr);
	if (will_need_frag_hdr(pkt_ip4_hdr(in)))
		headers += sizeof(struct frag_hdr);
	headers += pkt_l4hdr_len(in);

	return headers + payload;
}

static int allocate_fast(struct xlation *state, bool ignore_df,
		unsigned short gso_size)
{
	struct packet *in = &state->in;
	struct sk_buff *out;
	struct iphdr *hdr4_inner;
	struct frag_hdr *hdr_frag;
	struct skb_shared_info *shinfo;
	int delta;

	/* Dunno what happens when headroom is negative, so don't risk it. */
	delta = get_delta(in);
	if (delta < 0)
		delta = 0;

	/* Allocate the outgoing packet as a copy of @in with shared pages. */
	out = __pskb_copy(in->skb, delta + skb_headroom(in->skb), GFP_ATOMIC);
	if (!out) {
		log_debug("__pskb_copy() returned NULL.");
		return drop(state);
	}

	skb_cleanup_copy(out);

	/* Remove outer l3 and l4 headers from the copy. */
	skb_pull(out, pkt_hdrs_len(in));

	if (pkt_is_icmp4_error(in)) {
		hdr4_inner = pkt_payload(in);

		/* Remove inner l3 headers from the copy. */
		skb_pull(out, hdr4_inner->ihl << 2);

		/* Add inner l3 headers to the copy. */
		if (will_need_frag_hdr(hdr4_inner))
			skb_push(out, sizeof(struct frag_hdr));
		skb_push(out, sizeof(struct ipv6hdr));
	}

	/* Add outer l4 headers to the copy. */
	skb_push(out, pkt_l4hdr_len(in));

	/* Add outer l3 headers to the copy. */
	if (will_need_frag_hdr(pkt_ip4_hdr(in)))
		skb_push(out, sizeof(struct frag_hdr));
	skb_push(out, sizeof(struct ipv6hdr));

	skb_reset_mac_header(out);
	skb_reset_network_header(out);
	if (will_need_frag_hdr(pkt_ip4_hdr(in))) {
		hdr_frag = (struct frag_hdr *)(skb_network_header(out)
				+ sizeof(struct ipv6hdr));
		skb_set_transport_header(out, sizeof(struct ipv6hdr)
				+ sizeof(struct frag_hdr));
	} else {
		hdr_frag = NULL;
		skb_set_transport_header(out, sizeof(struct ipv6hdr));
	}

	/* Wrap up. */
	pkt_fill(&state->out, out, PF_INET6, proto2nexthdr(in->l4_proto),
		 hdr_frag, skb_transport_header(out) + pkt_l4hdr_len(in));

	memset(out->cb, 0, sizeof(out->cb));
	out->ignore_df = ignore_df;
	out->protocol = htons(ETH_P_IPV6);

	shinfo = skb_shinfo(out);
	if (shinfo->gso_size && gso_size)
		shinfo->gso_size = gso_size;
	if (shinfo->gso_type & SKB_GSO_TCPV4) {
		shinfo->gso_type &= ~SKB_GSO_TCPV4;
		shinfo->gso_type |= SKB_GSO_TCPV6;
	}

	return 0;
}

static int allocate_slow(struct xlation *state, unsigned int mpl)
{
	struct packet *in;
	struct sk_buff **previous;
	struct sk_buff *out;
	unsigned int payload_left; /* Payload not yet consumed */
	/* Amount of layer 3 payload we can include in each fragment */
	unsigned int payload_per_frag;
	/* Current fragment's layer 3 payload length */
	unsigned int fragment_payload_len;
	unsigned int bytes_consumed;
	struct frag_hdr *frag;
	unsigned char *l3_payload;

	in = &state->in;
	previous = &state->out.skb;
	payload_left = in->skb->len - pkt_l3hdr_len(in);
	payload_per_frag = (mpl - HDRS_LEN) & 0xFFFFFFF8U;
	bytes_consumed = 0;

	while (payload_left > 0) {
		if (payload_left > payload_per_frag) {
			fragment_payload_len = payload_per_frag;
			payload_left -= payload_per_frag;
		} else {
			fragment_payload_len = payload_left;
			payload_left = 0;
		}

		out = alloc_skb(skb_headroom(in->skb) + HDRS_LEN
				+ fragment_payload_len, GFP_ATOMIC);
		if (!out)
			goto fail;

		*previous = out;
		previous = &out->next;

		skb_reserve(out, skb_headroom(in->skb));
		skb_reset_mac_header(out);
		skb_reset_network_header(out);
		skb_put(out, sizeof(struct ipv6hdr));
		frag = (struct frag_hdr *)skb_put(out, sizeof(struct frag_hdr));
		l3_payload = skb_put(out, fragment_payload_len);

		skb_set_transport_header(out, HDRS_LEN);
		if (out == state->out.skb) {
			pkt_fill(&state->out, out, PF_INET6,
				 proto2nexthdr(in->l4_proto), frag,
				 l3_payload + pkt_l4hdr_len(in));
		}

		out->ignore_df = false;
		out->mark = in->skb->mark;
		out->protocol = htons(ETH_P_IPV6);

		if (skb_copy_bits(in->skb,
				skb_transport_offset(in->skb) + bytes_consumed,
				l3_payload, fragment_payload_len))
			goto fail;
		bytes_consumed += fragment_payload_len;
	}

	return 0;

fail:
	kfree_skb_list(state->out.skb);
	state->out.skb = NULL;
	return drop(state);
}

int ttp46_alloc_skb(struct xlation *state)
{
	/*
	 * Glossary:
	 *
	 * - In = Incoming packet
	 * - Out = Outgoing packet
	 * - IPL: Ideal (Outgoing) Packet Length
	 * - MPL: Maximum (allowed) Packet Length
	 * - LIM: lowest-ipv6-mtu (Configuration option)
	 * - Slow Path: Out packets will have to be created from scratch, data
	 *   will have to be copied from In to Out(s)
	 * - Fast Path: Out packet will share In packet's fragment and paged
	 *   data if possible
	 * - PTB: Packet Too Big (ICMPv6 error type 2 code 0)
	 * - FN: Fragmentation Needed (ICMPv4 error type 3 code 4)
	 *
	 * This is a pain in the ass because of lowest-ipv6-mtu and GRO/GSO.
	 * Slow Path undoes GRO, so we want to avoid it as much as possible.
	 *
	 * Design notes:
	 *
	 * # MTU
	 *
	 * MTU needs to be handled with extreme caution. We do not want
	 * ip6_output() -> ip6_finish_output() -> ip6_fragment() to return
	 * PTB because we want a FN instead. (We wouldn't translate
	 * ip6_fragment()'s PTB to FN because we're stuck in prerouting, so
	 * it wouldn't reach us.) PMTUD depends on this. We avoid the PTB by
	 * sending the FN ourselves by querying dst_mtu() (the same MTU function
	 * ip6_fragment() uses to compute the MTU).
	 *
	 * Of course, this hinges on ip6_fragment() using dst_mtu(). If this
	 * ever stops working, this is the first thing you need to check.
	 * (Hint: The struct sock is always NULL.)
	 *
	 * (If, on the other hand, a future namespace returns a PTB, it will
	 * cross our prerouting so it'll be converted to a FN no problem.)
	 *
	 * # Slow/Fast Path
	 *
	 * In Fast Path the result will be a single skb, sharing the incoming
	 * packet's frag_list and frags.
	 * In Slow Path the result will be multiple skbs, connected by their
	 * next pointers. (We don't need prev for anything.)
	 *
	 * At time of writing, we need Slow Path (ie. we need to fragment
	 * ourselves) for two reasons:
	 *
	 * 1. The kernel's IPv6 fragmentator doesn't care about already existing
	 *    fragment headers, which complicates the survival of the Fragment
	 *    Identification value needed when the packet is already fragmented.
	 *    If Jool sends an IPv6 packet containing a fragment header (hoping
	 *    that the kernel will reuse it if it needs to fragment), the kernel
	 *    will just add another fragment header instead.
	 * 2. We don't have a means to inform LIM to the kernel.
	 *
	 * Actually, I don't know if 2 is strictly true. I suppose we could
	 * override state->dst->dev->mtu, but because it's a shared structure,
	 * it's probably illegal.
	 *
	 * # GRO and GSO
	 *
	 * GRO/GSO are a problem because they lack contracts. I think the most
	 * helpful documentation I found was https://lwn.net/Articles/358910/,
	 * which has some interesting claims:
	 *
	 * - "the criteria for which packets can be merged is greatly
	 *   restricted; (...) only a few TCP or IP headers can differ."
	 * - "As a result of these restrictions, merged packets can be
	 *   resegmented losslessly; as an added benefit, the GSO code can be
	 *   used to perform resegmentation."
	 *
	 * In short, "GRO aims to be lossless, strict and symmetrical to GSO."
	 *
	 * Unfortunately, it doesn't say which are the fields that are allowed
	 * to differ. Thus I need to make assumptions based on my readings of
	 * the kernel code. This is obviously not future-proof, but it's
	 * basically needed because performance is severely restricted
	 * otherwise.
	 *
	 * I believe the relevant code is inet_gro_receive() (Hint: "^" is some
	 * funny guy's smartass way of saying "!="), and these are my
	 * assumptions:
	 *
	 * 1. DF is one of the fields which are not allowed to differ. If GSO is
	 * active, then I can assume that all DFs were enabled, or all DFs were
	 * disabled. This appears to be true for all currently supported
	 * kernels.
	 *
	 * 2. Thanks to gso_size, the original packet size (agreed upon by way
	 * of PMTUD) will not be mangled by GRO/GSO. I can assume this because
	 * PMTUD is sacred, and I can't see any way to reconcile it with GRO/GSO
	 * if the latter mangles packet sizes. (Though I must emphasize that I
	 * could be overlooking something.)
	 *
	 * 3. IPv4 GRO/GSO and IPv6 GRO/GSO basically function the same way (ie.
	 * a translated IPv4 GRO packet will be correctly segmented by the IPv6
	 * GSO code.) (This is the biggest stretch, and I really can't prove it
	 * definitely, but has worked fine so far.)
	 *
	 * So:
	 *
	 * 1. If fragmentation is prohibited, GSO does not prevent us from using
	 * Fast Path, because it preserves packet sizes. This is awesome.
	 *
	 * 2. If fragmentation is allowed, GSO might lead us to translate a
	 * large DF-disabled IPv4 packet into a large IPv6 packet, so we need to
	 * impose LIM. If the packet is already fragmented, we need to preserve
	 * the Fragmentation ID, which AFAIK, is impossible through the kernel
	 * API. Therefore, Slow Path.
	 *
	 * (Note: GRO enabled on !DF suggests there might exist some potential
	 * optimization I could be missing somewhere.)
	 *
	 * Therefore: If users want performance, they need to enable DF or GTFO.
	 *
	 * # LRO
	 *
	 * a) I don't know how it works. (eg. Does it affect skb_is_gso()?)
	 * b) I'm assuming it's always disabled nowadays. (Corollary: I can't
	 *    test it because I can't find any hardware that supports it.)
	 * c) It's lossy, which means it might be inherently incompatible with
	 *    IP XLAT.
	 * d) The code is already convoluted enough as it is.
	 * e) I think it was obsoleted many kernels ago?
	 * f) I don't care.
	 *
	 * LRO is not supported.
	 */

	struct packet *in;
	unsigned int nexthop_mtu;
	unsigned int mpl;
	unsigned int out_len;

	in = &state->in;
	nexthop_mtu = state->dev->mtu;
	mpl = min(nexthop_mtu, state->cfg->lowest_ipv6_mtu);
	if (mpl < 1280)
		return drop(state);

	if (pkt_is_icmp4_error(in)) {
		/*
		 * Fragment header will never be added because ICMP error,
		 * so Fast Path is always viable.
		 */
		return allocate_fast(state, false, 0);
	}

	out_len = fragment_exceeds_mtu46(in);

	if (is_df_set(pkt_ip4_hdr(in))) {
		/*
		 * Good; sender is not a dumbass.
		 * Fragment header will only be included if already fragmented.
		 */
		if (out_len > nexthop_mtu) {
			log_debug("Translated packet is too big (%u) for nexthop MTU (%u)",
				out_len, nexthop_mtu);
			return drop_icmp(state, ICMP_DEST_UNREACH,
					ICMP_FRAG_NEEDED,
					max(576u, nexthop_mtu - 20u));
		} else {
			return allocate_fast(state, in->skb->ignore_df,
					skb_shinfo(in->skb)->gso_size);
		}
	}

	if (out_len > mpl) {
		/*
		 * Force LIM and Fragmentation ID preservation through manual
		 * fragmentation.
		 */
		return allocate_slow(state, mpl);
	}

	/*
	 * Dodged a bullet; no need to fragment further, we'll just
	 * build the Fragmentation header ourselves.
	 */
	return allocate_fast(state, false, 0);
}

/**
 * Returns "true" if "hdr" contains a source route option and the last address
 * from it hasn't been reached.
 *
 * Assumes the options are glued in memory after "hdr", the way sk_buffs work
 * (when linearized or pullable).
 */
static bool has_unexpired_src_route(struct iphdr *hdr)
{
	unsigned char *current_opt, *end_of_opts;
	__u8 src_route_len, src_route_ptr;

	/* Find a loose source route or a strict source route option. */
	current_opt = (unsigned char *)(hdr + 1);
	end_of_opts = ((unsigned char *)hdr) + (4 * hdr->ihl);
	if (current_opt >= end_of_opts)
		return false;

	while (current_opt[0] != IPOPT_LSRR && current_opt[0] != IPOPT_SSRR) {
		switch (current_opt[0]) {
		case IPOPT_END:
			return false;
		case IPOPT_NOOP:
			current_opt++;
			break;
		default:
			/*
			 * IPOPT_SEC, IPOPT_RR, IPOPT_SID, IPOPT_TIMESTAMP,
			 * IPOPT_CIPSO and IPOPT_RA are known to fall through
			 * here.
			 */
			current_opt += current_opt[1];
			break;
		}

		if (current_opt >= end_of_opts)
			return false;
	}

	/* Finally test. */
	src_route_len = current_opt[1];
	src_route_ptr = current_opt[2];
	return src_route_len >= src_route_ptr;
}

/**
 * One-liner for creating the Identification field of the IPv6 Fragment header.
 */
static inline __be32 build_id_field(struct iphdr *hdr4)
{
	return cpu_to_be32(be16_to_cpu(hdr4->id));
}

/*
 * Copies the IPv6 and fragment headers from the first fragment to the
 * subsequent ones, adapting fields appropriately.
 */
static void autofill_hdr6(struct packet *out)
{
	struct sk_buff *first;
	struct sk_buff *skb;
	struct ipv6hdr *hdr6;
	struct frag_hdr *frag;
	__u16 frag_offset;
	__u16 first_mf;

	first = out->skb;
	if (!first->next)
		return;

	frag = (struct frag_hdr *)(ipv6_hdr(first) + 1);
	frag_offset = get_fragment_offset_ipv6(frag) + first->len - HDRS_LEN;
	first_mf = is_mf_set_ipv6(frag);
	frag->frag_off |= cpu_to_be16(IP6_MF);

	for (skb = first->next; skb != NULL; skb = skb->next) {
		hdr6 = ipv6_hdr(skb);
		frag = (struct frag_hdr *)(hdr6 + 1);

		memcpy(hdr6, ipv6_hdr(first), HDRS_LEN);
		hdr6->payload_len = cpu_to_be16(skb->len - sizeof(*hdr6));
		frag->frag_off = build_ipv6_frag_off_field(frag_offset,
				skb->next ? true : first_mf);

		frag_offset += skb->len - HDRS_LEN;
	}
}

static int ttcp46_ipv6_common(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct iphdr *hdr4 = pkt_ip4_hdr(in);
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	struct frag_hdr *frag_header;
	int error;

	hdr6->version = 6;
	if (state->cfg->reset_traffic_class) {
		hdr6->priority = 0;
		hdr6->flow_lbl[0] = 0;
	} else {
		hdr6->priority = hdr4->tos >> 4;
		hdr6->flow_lbl[0] = hdr4->tos << 4;
	}
	hdr6->flow_lbl[1] = 0;
	hdr6->flow_lbl[2] = 0;
	/* hdr6->payload_len */
	/* hdr6->nexthdr */
	if (pkt_is_outer(in)) {
		if (hdr4->ttl <= 1) {
			log_debug("Packet's TTL <= 1.");
			return drop_icmp(state, ICMP_TIME_EXCEEDED,
					ICMP_EXC_TTL, 0);
		}
		hdr6->hop_limit = hdr4->ttl - 1;
	} else {
		hdr6->hop_limit = hdr4->ttl;
	}

	error = siit46_addrs(state, &hdr6->saddr, &hdr6->daddr);
	if (error)
		return error;

	if (will_need_frag_hdr(hdr4) || out->skb->next) {
		frag_header = (struct frag_hdr *)(hdr6 + 1);
		frag_header->nexthdr = hdr6->nexthdr;
		hdr6->nexthdr = NEXTHDR_FRAGMENT;
		frag_header->reserved = 0;
		frag_header->frag_off = build_ipv6_frag_off_field(
				get_fragment_offset_ipv4(hdr4),
				is_mf_set_ipv4(hdr4));
		frag_header->identification = build_id_field(hdr4);
	}

	return 0;
}

/* RFC 7915, section 4.1. */
int ttp46_ipv6_external(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	int error;

	if (pkt_is_outer(in) && has_unexpired_src_route(pkt_ip4_hdr(in))) {
		log_debug("Packet has an unexpired source route.");
		return drop_icmp(state, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
	}

	hdr6->nexthdr = state->out.l4_proto;
	/*
	 * I was tempted to use the RFC formula, but it's a little difficult
	 * because we can't trust the incoming packet's total length when we
	 * need to fragment due to lowest-ipv6-mtu.
	 * Also, this avoids the need to handle differently depending on whether
	 * we're adding a fragment header.
	 */
	hdr6->payload_len = cpu_to_be16(out->skb->len - sizeof(struct ipv6hdr));

	error = ttcp46_ipv6_common(state);
	if (error)
		return error;

	autofill_hdr6(out);
	return 0;
}

static int ttp46_ipv6_internal(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);

	hdr6->nexthdr = state->out.l4_proto;
	/*
	 * The RFC formula is fine, but this avoids the need to handle
	 * differently depending on whether we're adding a fragment header.
	 */
	hdr6->payload_len = cpu_to_be16(be16_to_cpu(pkt_ip4_hdr(in)->tot_len)
			    - pkt_hdrs_len(in)
			    + pkt_hdrs_len(out)
			    - sizeof(struct ipv6hdr));

	return ttcp46_ipv6_common(state);
}

/**
 * One liner for creating the ICMPv6 header's MTU field.
 * Returns the smallest out of the three first parameters. It also handles some
 * quirks. See comments inside for more info.
 */
static __be32 icmp6_minimum_mtu(struct xlation *state,
		unsigned int packet_mtu,
		unsigned int nexthop6_mtu,
		unsigned int nexthop4_mtu,
		__u16 tot_len_field)
{
	__u32 result;

	if (packet_mtu == 0) {
		/*
		 * Some router does not implement RFC 1191.
		 * Got to determine a likely path MTU.
		 * See RFC 1191 sections 5, 7 and 7.1.
		 */
		__u16 *plateaus = state->cfg->plateaus.values;
		__u16 count = state->cfg->plateaus.count;
		int i;

		for (i = 0; i < count; i++) {
			if (plateaus[i] < tot_len_field) {
				packet_mtu = plateaus[i];
				break;
			}
		}
	}

	/* Here's the core comparison. */
	result = min(packet_mtu + 20, min(nexthop6_mtu, nexthop4_mtu + 20));
	if (result < IPV6_MIN_MTU)
		result = IPV6_MIN_MTU;

	return cpu_to_be32(result);
}

static int compute_mtu6(struct xlation *state)
{
	/* Meant for hairpinning and unit tests. */
	static const unsigned int INFINITE = 0xffffffff;
	struct net_device *in_dev;
	struct dst_entry *out_dst;
	struct icmphdr *in_icmp;
	struct icmp6hdr *out_icmp;
	struct iphdr *hdr4;
	unsigned int in_mtu;
	unsigned int out_mtu;

	in_icmp = pkt_icmp4_hdr(&state->in);
	out_icmp = pkt_icmp6_hdr(&state->out);
	in_dev = state->in.skb->dev;
	in_mtu = in_dev ? in_dev->mtu : INFINITE;
	out_dst = skb_dst(state->out.skb);
	out_mtu = out_dst ? dst_mtu(out_dst) : INFINITE;

	log_debug("Packet MTU: %u", be16_to_cpu(in_icmp->un.frag.mtu));
	log_debug("In dev MTU: %u", in_mtu);
	log_debug("Out dev MTU: %u", out_mtu);

	/*
	 * We want the length of the packet that couldn't get through,
	 * not the truncated one.
	 */
	hdr4 = pkt_payload(&state->in);
	out_icmp->icmp6_mtu = icmp6_minimum_mtu(state,
			be16_to_cpu(in_icmp->un.frag.mtu),
			out_mtu,
			in_mtu,
			be16_to_cpu(hdr4->tot_len));
	log_debug("Resulting MTU: %u", be32_to_cpu(out_icmp->icmp6_mtu));

	return 0;
}

/**
 * One-liner for translating "Destination Unreachable" messages from ICMPv4 to
 * ICMPv6.
 */
static int icmp4_to_icmp6_dest_unreach(struct xlation *state)
{
	struct icmphdr *icmp4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmp6_hdr = pkt_icmp6_hdr(&state->out);

	switch (icmp4_hdr->code) {
	case ICMP_NET_UNREACH:
	case ICMP_HOST_UNREACH:
	case ICMP_SR_FAILED:
	case ICMP_NET_UNKNOWN:
	case ICMP_HOST_UNKNOWN:
	case ICMP_HOST_ISOLATED:
	case ICMP_NET_UNR_TOS:
	case ICMP_HOST_UNR_TOS:
	case ICMP_PORT_UNREACH:
	case ICMP_NET_ANO:
	case ICMP_HOST_ANO:
	case ICMP_PKT_FILTERED:
	case ICMP_PREC_CUTOFF:
		icmp6_hdr->icmp6_unused = 0;
		return 0;

	case ICMP_PROT_UNREACH:
		icmp6_hdr->icmp6_pointer = cpu_to_be32(offsetof(struct ipv6hdr,
				nexthdr));
		return 0;

	case ICMP_FRAG_NEEDED:
		return compute_mtu6(state);
	}

	/* Dead code */
	WARN(1, "ICMPv4 Destination Unreachable code %u was unhandled by the switch above.",
			icmp4_hdr->code);
	return drop(state);
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv4 to ICMPv6.
 */
static int icmp4_to_icmp6_param_prob(struct xlation *state)
{
#define DROP 255
	static const __u8 ptrs[] = {
		0,    1,    4,    4,
		DROP, DROP, DROP, DROP,
		7,    6,    DROP, DROP,
		8,    8,    8,    8,
		24,   24,   24,   24
	};

	struct icmphdr *icmp4_hdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *icmp6_hdr = pkt_icmp6_hdr(&state->out);
	__u8 ptr;

	switch (icmp4_hdr->code) {
	case ICMP_PTR_INDICATES_ERROR:
	case ICMP_BAD_LENGTH:
		ptr = be32_to_cpu(icmp4_hdr->icmp4_unused) >> 24;

		if (19 < ptr || ptrs[ptr] == DROP) {
			log_debug("ICMPv4 messages type %u code %u pointer %u lack an ICMPv6 counterpart.",
					icmp4_hdr->type, icmp4_hdr->code, ptr);
			return drop(state);
		}

		icmp6_hdr->icmp6_pointer = cpu_to_be32(ptrs[ptr]);
		return 0;
	}

	/* Dead code */
	WARN(1, "ICMPv4 Parameter Problem code %u was unhandled by the switch above.",
			icmp4_hdr->code);
	return drop(state);
}

/*
 * Removes L4 header, adds L4 header, adds IPv6 pseudoheader.
 */
static void update_icmp6_csum(struct xlation *state)
{
	struct ipv6hdr *out_ip6 = pkt_ip6_hdr(&state->out);
	struct icmphdr *in_icmp = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *out_icmp = pkt_icmp6_hdr(&state->out);
	struct icmphdr copy_hdr;
	__wsum csum;

	out_icmp->icmp6_cksum = 0;

	csum = ~csum_unfold(in_icmp->checksum);

	memcpy(&copy_hdr, in_icmp, sizeof(*in_icmp));
	copy_hdr.checksum = 0;
	csum = csum_sub(csum, csum_partial(&copy_hdr, sizeof(copy_hdr), 0));

	csum = csum_add(csum, csum_partial(out_icmp, sizeof(*out_icmp), 0));

	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr,
			&out_ip6->daddr, pkt_datagram_len(&state->in),
			IPPROTO_ICMPV6, csum);
}

static int validate_icmp4_csum(struct xlation *state)
{
	struct packet *in = &state->in;
	__sum16 csum;

	if (in->skb->ip_summed != CHECKSUM_NONE)
		return 0;

	csum = csum_fold(skb_checksum(in->skb, skb_transport_offset(in->skb),
			pkt_datagram_len(in), 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return drop(state);
	}

	return 0;
}

static bool should_remove_ie(struct xlation *state)
{
	struct icmphdr *hdr;
	__u8 type;
	__u8 code;

	hdr = pkt_icmp4_hdr(&state->in);
	type = hdr->type;
	code = hdr->code;

	/* v4 Protocol Unreachable becomes v6 Parameter Problem. */
	if (type == 3 && code == 2)
		return true;
	/* v4 Fragmentation Needed becomes v6 Packet Too Big. */
	if (type == 3 && code == 4)
		return true;
	/* v4 Parameter Problem becomes v6 Parameter Problem. */
	if (type == 12)
		return true;

	return false;
}

static int handle_icmp6_extension(struct xlation *state)
{
	struct icmpext_args args;
	struct packet *out;
	int error;

	args.max_pkt_len = 1280;
	args.ipl = icmp4_length(pkt_icmp4_hdr(&state->in)) << 2;
	args.out_bits = 3;
	args.force_remove_ie = should_remove_ie(state);

	error = handle_icmp_extension(state, &args);
	if (error)
		return error;

	out = &state->out;
	pkt_icmp6_hdr(out)->icmp6_length = args.ipl;
	pkt_ip6_hdr(out)->payload_len = cpu_to_be16(out->skb->len
			- sizeof(struct ipv6hdr));
	return 0;
}

/*
 * Though ICMPv4 errors are supposed to be max 576 bytes long, a good portion of
 * the Internet seems prepared against bigger ICMPv4 errors. Thus, the resulting
 * ICMPv6 packet might have a smaller payload than the original packet even
 * though IPv4 MTU < IPv6 MTU.
 */
static int trim_1280(struct xlation *state)
{
	struct packet *out;
	int error;

	out = &state->out;
	if (out->skb->len <= 1280)
		return 0;

	error = pskb_trim(out->skb, 1280);
	if (error) {
		log_debug("pskb_trim() error: %d", error);
		return drop(state);
	}

	pkt_ip6_hdr(out)->payload_len = cpu_to_be16(out->skb->len
			- sizeof(struct ipv6hdr));
	return 0;
}

static int post_icmp6error(struct xlation *state)
{
	static const struct translation_steps xsteps = {
		.xlat_l3 = ttp46_ipv6_internal,
		.xlat_tcp = ttp46_tcp,
		.xlat_udp = ttp46_udp,
		.xlat_icmp = ttp46_icmp,
	};
	int error;

	log_debug("Translating the inner packet (4->6)...");

	/*
	 * We will later recompute the checksum from scratch, but we should not
	 * translate a corrupted ICMPv4 error into an OK-csum ICMPv6 one,
	 * so validate first.
	 */
	error = validate_icmp4_csum(state);
	if (error)
		return error;

	error = ttpcomm_translate_inner_packet(state, &xsteps);
	if (error)
		return error;

	error = handle_icmp6_extension(state);
	if (error)
		return error;

	error = trim_1280(state);
	if (error)
		return error;

	compute_icmp6_csum(state->out.skb);
	return 0;
}

static int echo(struct xlation *state, struct icmphdr const *icmp4,
		struct icmp6hdr *icmp6, __u8 type)
{
	icmp6->icmp6_type = type;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_identifier = icmp4->un.echo.id;
	icmp6->icmp6_sequence = icmp4->un.echo.sequence;
	update_icmp6_csum(state);
	return 0;
}

/**
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 7915 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
int ttp46_icmp(struct xlation *state)
{
	struct icmphdr *inhdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *outhdr = pkt_icmp6_hdr(&state->out);
	int error;

	outhdr->icmp6_cksum = inhdr->checksum; /* Updated later */

	/* -- First the ICMP header. -- */
	switch (inhdr->type) {
	case ICMP_ECHO:
		return echo(state, inhdr, outhdr, ICMPV6_ECHO_REQUEST);
	case ICMP_ECHOREPLY:
		return echo(state, inhdr, outhdr, ICMPV6_ECHO_REPLY);

	case ICMP_DEST_UNREACH:
		switch (inhdr->code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
		case ICMP_SR_FAILED:
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			outhdr->icmp6_type = ICMPV6_DEST_UNREACH;
			outhdr->icmp6_code = ICMPV6_NOROUTE;
			break;

		case ICMP_PROT_UNREACH:
			outhdr->icmp6_type = ICMPV6_PARAMPROB;
			outhdr->icmp6_code = ICMPV6_UNK_NEXTHDR;
			break;

		case ICMP_PORT_UNREACH:
			outhdr->icmp6_type = ICMPV6_DEST_UNREACH;
			outhdr->icmp6_code = ICMPV6_PORT_UNREACH;
			break;

		case ICMP_FRAG_NEEDED:
			outhdr->icmp6_type = ICMPV6_PKT_TOOBIG;
			outhdr->icmp6_code = 0;
			break;

		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
		case ICMP_PREC_CUTOFF:
			outhdr->icmp6_type = ICMPV6_DEST_UNREACH;
			outhdr->icmp6_code = ICMPV6_ADM_PROHIBITED;
			break;
		default:
			goto fail;
		}

		error = icmp4_to_icmp6_dest_unreach(state);
		if (error)
			return error;
		return post_icmp6error(state);

	case ICMP_TIME_EXCEEDED:
		outhdr->icmp6_type = ICMPV6_TIME_EXCEED;
		outhdr->icmp6_code = inhdr->code;
		outhdr->icmp6_unused = 0;
		return post_icmp6error(state);

	case ICMP_PARAMETERPROB:
		outhdr->icmp6_type = ICMPV6_PARAMPROB;
		switch (inhdr->code) {
		case ICMP_PTR_INDICATES_ERROR:
		case ICMP_BAD_LENGTH:
			outhdr->icmp6_code = ICMPV6_HDR_FIELD;
			break;
		default:
			goto fail;
		}
		error = icmp4_to_icmp6_param_prob(state);
		if (error)
			return error;
		return post_icmp6error(state);
	}

fail:
	/*
	 * The following codes are known to fall through here:
	 * Information Request/Reply (15, 16), Timestamp and Timestamp Reply
	 * (13, 14), Address Mask Request/Reply (17, 18), Router Advertisement
	 * (9), Router Solicitation (10), Source Quench (4), Redirect (5),
	 * Alternative Host Address (6).
	 * This time there's no ICMP error.
	 */
	log_debug("ICMPv4 messages type %u code %u lack an ICMPv6 counterpart.",
			inhdr->type, inhdr->code);
	return drop(state);
}

/*
 * Computes the L4 checksum from scratch for Slow Path packet @out.
 */
static __sum16 skb_list_csum(struct sk_buff *out, __u8 proto)
{
	struct sk_buff *skb;
	__wsum csum;
	int l4_offset;
	int cursor_len;
	int total_len;

	csum = 0;
	cursor_len = 0;
	total_len = 0;
	for (skb = out; skb; skb = skb->next) {
		l4_offset = skb_transport_offset(skb);
		cursor_len = skb->len - l4_offset;
		csum = skb_checksum(skb, l4_offset, cursor_len, csum);
		total_len += cursor_len;
	}

	return csum_ipv6_magic(&ipv6_hdr(out)->saddr, &ipv6_hdr(out)->daddr,
			total_len, proto, csum);
}

/**
 * Removes the IPv4 pseudoheader and L4 header, adds the IPv6 pseudoheader and
 * L4 header. Input and result are folded.
 */
static __sum16 update_csum_4to6(__sum16 csum16,
		struct iphdr *in_ip4, void *in_l4_hdr,
		struct ipv6hdr *out_ip6, void *out_l4_hdr,
		size_t l4_hdr_len)
{
	__wsum csum, pseudohdr_csum;

	/* See comments at update_csum_6to4(). */

	csum = ~csum_unfold(csum16);

	pseudohdr_csum = csum_tcpudp_nofold(in_ip4->saddr, in_ip4->daddr,
			0, 0, 0);
	csum = csum_sub(csum, pseudohdr_csum);
	csum = csum_sub(csum, csum_partial(in_l4_hdr, l4_hdr_len, 0));

	pseudohdr_csum = ~csum_unfold(csum_ipv6_magic(&out_ip6->saddr,
			&out_ip6->daddr, 0, 0, 0));
	csum = csum_add(csum, pseudohdr_csum);
	csum = csum_add(csum, csum_partial(out_l4_hdr, l4_hdr_len, 0));

	return csum_fold(csum);
}

static bool can_compute_csum(struct xlation *state)
{
	struct iphdr *hdr4;
	struct udphdr *hdr_udp;
	bool amend_csum0;

	/*
	 * RFC 7915#4.5:
	 * A stateless translator cannot compute the UDP checksum of
	 * fragmented packets, so when a stateless translator receives the
	 * first fragment of a fragmented UDP IPv4 packet and the checksum
	 * field is zero, the translator SHOULD drop the packet and generate
	 * a system management event that specifies at least the IP
	 * addresses and port numbers in the packet.
	 *
	 * The "system management event" is outside. (See
	 * JSTAT46_FRAGMENTED_ZERO_CSUM.)
	 * It does not include the addresses/ports, which is OK because users
	 * don't like it: https://github.com/NICMx/Jool/pull/129
	 */
	hdr4 = pkt_ip4_hdr(&state->in);
	amend_csum0 = state->cfg->compute_udp_csum_zero;
	if (is_mf_set_ipv4(hdr4) || !amend_csum0) {
		hdr_udp = pkt_udp_hdr(&state->in);
		log_debug("Dropping zero-checksum UDP packet: %pI4#%u->%pI4#%u",
				&hdr4->saddr, ntohs(hdr_udp->source),
				&hdr4->daddr, ntohs(hdr_udp->dest));
		return false;
	}

	return true;
}

int ttp46_tcp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct tcphdr *tcp_in = pkt_tcp_hdr(in);
	struct tcphdr *tcp_out = pkt_tcp_hdr(out);
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, pkt_l4hdr_len(in));

	/* Header.checksum */
	if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
		memcpy(&tcp_copy, tcp_in, sizeof(*tcp_in));
		tcp_copy.check = 0;

		tcp_out->check = 0;
		tcp_out->check = update_csum_4to6(tcp_in->check,
				pkt_ip4_hdr(in), &tcp_copy,
				pkt_ip6_hdr(out), tcp_out,
				sizeof(*tcp_out));

	} else if (out->skb->next) {
		tcp_out->check = 0;
		tcp_out->check = skb_list_csum(out->skb, NEXTHDR_TCP);

	} else {
		tcp_out->check = ~tcp_v6_check(pkt_datagram_len(out),
				&pkt_ip6_hdr(out)->saddr,
				&pkt_ip6_hdr(out)->daddr, 0);
		partialize_skb(out->skb, offsetof(struct tcphdr, check));
	}

	return 0;
}

int ttp46_udp(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct udphdr *udp_in = pkt_udp_hdr(in);
	struct udphdr *udp_out = pkt_udp_hdr(out);
	struct udphdr udp_copy;

	/* Header */
	memcpy(udp_out, udp_in, pkt_l4hdr_len(in));

	/* Header.checksum */
	if (udp_in->check == 0) {
		if (can_compute_csum(state))
			goto partial;

		return drop_icmp(state, ICMP_DEST_UNREACH, ICMP_PKT_FILTERED, 0);

	} else if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
		memcpy(&udp_copy, udp_in, sizeof(*udp_in));
		udp_copy.check = 0;

		udp_out->check = 0;
		udp_out->check = update_csum_4to6(udp_in->check,
				pkt_ip4_hdr(in), &udp_copy,
				pkt_ip6_hdr(out), udp_out,
				sizeof(*udp_out));

	} else if (out->skb->next) {
		udp_out->check = 0;
		udp_out->check = skb_list_csum(out->skb, NEXTHDR_UDP);

	} else {
		goto partial;
	}

	return 0;

partial:
	udp_out->check = ~udp_v6_check(pkt_datagram_len(out),
			&pkt_ip6_hdr(out)->saddr,
			&pkt_ip6_hdr(out)->daddr, 0);
	partialize_skb(out->skb, offsetof(struct udphdr, check));
	return 0;
}

/*
 * TODO Maaaaaaaaybe replace this with icmp_send().
 * I'm afraid of using such a high level function from here, tbh.
 */
void ttp46_icmp_err(struct xlation *state)
{
	struct sk_buff *in = state->in.skb;
	struct sk_buff *out;
	struct iphdr *iph;
	struct icmphdr *ich;
	bool allow;
	unsigned int len;

	if (in->pkt_type != PACKET_HOST)
		return;
	if (ip_hdr(in)->frag_off & htons(IP_OFFSET))
		return;
	if (pkt_is_icmp4_error(&state->in))
		return;

	local_bh_disable();
	allow = icmp_global_allow();
	local_bh_enable();
	if (!allow)
		return;

	len = sizeof(*iph) + sizeof(*ich) + in->len;
	if (len > 576u)
		len = 576u;

	out = netdev_alloc_skb(state->dev, LL_MAX_HEADER + len);
	if (!out)
		return;

	skb_reserve(out, LL_MAX_HEADER);
	skb_put(out, len);
	skb_reset_mac_header(out);
	skb_reset_network_header(out);
	skb_set_transport_header(out, sizeof(struct iphdr));

	iph = ip_hdr(out);
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = htons(len);
	iph->id = 0;
	iph->frag_off = build_ipv4_frag_off_field(1, 0, 0);
	iph->ttl = 255;
	iph->protocol = IPPROTO_ICMP;
	iph->saddr = htonl(INADDR_DUMMY); /* TODO variabilize */
//	iph->saddr = htonl(0xc6336401); /* Graybox tests version */
	iph->daddr = ip_hdr(in)->saddr;
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	ich = icmp_hdr(out);
	ich->type = state->result.type;
	ich->code = state->result.code;
	/* checksum later */
	ich->icmp4_unused = htonl(state->result.info);

	if (skb_copy_bits(in, 0, ich + 1, len - sizeof(*iph) - sizeof(*ich))) {
		dev_kfree_skb(out);
		return;
	}

	compute_icmp4_csum(out);
	out->mark = IP4_REPLY_MARK(state->ns, in->mark);
	out->protocol = htons(ETH_P_IP);

	memset(&state->out, 0, sizeof(state->out));
	state->out.skb = out;
}
