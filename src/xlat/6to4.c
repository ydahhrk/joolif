#include "6to4.h"

#include <linux/inetdevice.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/addrconf.h>

#include "address.h"
#include "common.h"
#include "ipv6_hdr_iterator.h"
#include "log.h"

static __u8 xlat_tos(struct jool_globals const *config, struct ipv6hdr const *hdr)
{
	return config->reset_tos ? config->new_tos : get_traffic_class(hdr);
}

static __u8 nexthdr2proto(__u8 nexthdr)
{
	return (nexthdr == NEXTHDR_ICMP) ? IPPROTO_ICMP : nexthdr;
}

/**
 * One-liner for creating the IPv4 header's Protocol field.
 */
static __u8 xlat_proto(struct ipv6hdr const *hdr6)
{
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr6);
	hdr_iterator_last(&iterator);
	return nexthdr2proto(iterator.hdr_type);
}

/*
 * Returns:
 * 0: Packet does not exceed MTU.
 * 1: First fragment exceeds MTU. (ie. PTB needed)
 * 2: Subsequent fragment exceeds MTU. (ie. PTB not needed)
 */
static int fragment_exceeds_mtu64(struct packet const *in, unsigned int mtu)
{
	struct sk_buff *iter;
	unsigned short gso_size;
	int delta;

	/*
	 * shinfo->gso_size is the value the kernel uses (during resegmentation)
	 * to remember the length of the original segments after GRO.
	 *
	 * Interestingly, if packet A has frag_list fragments B, and B have
	 * frags fragments C, then A's gso_size also applies to B, as well as C.
	 *
	 * (Note: Ugh. This comment is old. I don't remember if I checked
	 * whether B's gso_size was nonzero.)
	 *
	 * I don't know if gso_size can be populated if there are frag_list
	 * fragments but not frags fragments. Luckily, this code should work
	 * either way.
	 *
	 * See ip_exceeds_mtu() and ip6_pkt_too_big().
	 */

	gso_size = skb_shinfo(in->skb)->gso_size;
	if (gso_size) {
		if (sizeof(struct iphdr) + pkt_l4hdr_len(in) + gso_size > mtu)
			goto generic_too_big;
		return 0;
	}

	delta = sizeof(struct iphdr) - pkt_l3hdr_len(in);
	if (skb_headlen(in->skb) + delta > mtu)
		goto generic_too_big;

	/*
	 * TODO (performance) This loop could probably be optimized away by
	 * querying IP6CB(skb)->frag_max_size. You'll have to test it.
	 */
	mtu -= sizeof(struct iphdr);
	skb_walk_frags(in->skb, iter)
		if (iter->len > mtu)
			return 2;

	return 0;

generic_too_big:
	return is_first_frag6(pkt_frag_hdr(in)) ? 1 : 2;
}

static int validate_size(struct xlation *state)
{
	unsigned int nexthop_mtu;

	nexthop_mtu = state->dev->mtu;
	switch (fragment_exceeds_mtu64(&state->in, nexthop_mtu)) {
	case 0:
		return 0;
	case 1:
		return drop_icmp(state, ICMPV6_PKT_TOOBIG, 0,
				max(1280u, nexthop_mtu + 20u));
	case 2:
		return drop(state);
	}

	WARN(1, "fragment_exceeds_mtu64() returned garbage.");
	return drop(state);
}

int ttp64_alloc_skb(struct xlation *state)
{
	struct packet const *in = &state->in;
	struct sk_buff *out;
	struct skb_shared_info *shinfo;
	int error;

	error = validate_size(state);
	if (error)
		return error;

	/*
	 * pskb_copy() is more efficient than allocating a new packet, because
	 * it shares (not copies) the original's paged data with the copy. This
	 * is great, because we don't need to modify the payload in either
	 * packet.
	 *
	 * Since the IPv4 version of the packet is going to be invariably
	 * smaller than its IPv6 counterpart, you'd think we should reserve less
	 * memory for it. But there's a problem: __pskb_copy() only allows us to
	 * shrink the headroom; not the head. If we try to shrink the head
	 * through the headroom and the v6 packet happens to have one too many
	 * extension headers, the `headroom` we'll send to __pskb_copy() will be
	 * negative, and then skb_copy_from_linear_data() will write onto the
	 * tail area without knowing it. (I'm reading the Linux 4.4 code.)
	 *
	 * We will therefore *not* attempt to allocate less.
	 */

	out = pskb_copy(in->skb, GFP_ATOMIC);
	if (!out) {
		log_debug("pskb_copy() returned NULL.");
		return drop(state);
	}

	skb_cleanup_copy(out);

	/* Remove outer l3 and l4 headers from the copy. */
	skb_pull(out, pkt_hdrs_len(in));

	if (is_first_frag6(pkt_frag_hdr(in)) && pkt_is_icmp6_error(in)) {
		struct ipv6hdr *hdr = pkt_payload(in);
		struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr);
		hdr_iterator_last(&iterator);

		/* Remove inner l3 headers from the copy. */
		skb_pull(out, iterator.data - (void *)hdr);

		/* Add inner l3 headers to the copy. */
		skb_push(out, sizeof(struct iphdr));
	}

	/* Add outer l4 headers to the copy. */
	skb_push(out, pkt_l4hdr_len(in));
	/* Add outer l3 headers to the copy. */
	skb_push(out, sizeof(struct iphdr));

	skb_reset_mac_header(out);
	skb_reset_network_header(out);
	skb_set_transport_header(out, sizeof(struct iphdr));

	/* Wrap up. */
	pkt_fill(&state->out, out, PF_INET, nexthdr2proto(in->l4_proto),
		 NULL, skb_transport_header(out) + pkt_l4hdr_len(in));

	memset(out->cb, 0, sizeof(out->cb));
	out->protocol = htons(ETH_P_IP);

	shinfo = skb_shinfo(out);
	if (shinfo->gso_type & SKB_GSO_TCPV6) {
		shinfo->gso_type &= ~SKB_GSO_TCPV6;
		shinfo->gso_type |= SKB_GSO_TCPV4;
	}

	return 0;
}

/**
 * One-liner for creating the IPv4 header's Identification field.
 *
 * Note, because of __ip_select_ident(), the following fields need to be already
 * set: hdr4->saddr, hdr4->daddr, hdr4->protocol.
 */
static void generate_ipv4_id(struct xlation const *state, struct iphdr *hdr4,
    struct frag_hdr const *hdr_frag)
{
	if (hdr_frag) {
		hdr4->id = cpu_to_be16(be32_to_cpu(hdr_frag->identification));
	} else {
		__ip_select_ident(state->ns, hdr4, 1);
	}
}

static bool generate_df_flag(struct xlation const *state)
{
	struct packet const *in;
	struct packet const *out;

	/*
	 * This is the RFC logic, but it's complicated by frag_list, GRO and
	 * internal packets.
	 */

	in = &state->in;
	out = &state->out;

	if (pkt_is_inner(out)) {
		/* Unimportant. Guess: RFC logic. Meh. */
		return ntohs(pkt_ip4_hdr(out)->tot_len) > 1260;
	}
	if (skb_has_frag_list(in->skb)) {
		/* Clearly fragmented */
		return false;
	}
	if (skb_is_gso(in->skb)) {
		if (in->l4_proto != IPPROTO_TCP) {
			/* UDP fragmented, ICMP & OTHER undefined */
			return false;
		}
		/* TCP not fragmented */
		return pkt_hdrs_len(out) + skb_shinfo(in->skb)->gso_size > 1260;
	}

	/* Not fragmented */
	return out->skb->len > 1260;
}

static __be16 xlat_frag_off(struct frag_hdr const *hdr_frag,
		struct xlation const *state)
{
	bool df;
	__u16 mf;
	__u16 frag_offset;

	if (hdr_frag) {
		df = 0;
		mf = is_mf_set_ipv6(hdr_frag);
		frag_offset = get_fragment_offset_ipv6(hdr_frag);
	} else {
		df = generate_df_flag(state);
		mf = 0;
		frag_offset = 0;
	}

	return build_ipv4_frag_off_field(df, mf, frag_offset);
}

/**
 * has_nonzero_segments_left - Returns true if @hdr6's packet has a routing
 * header, and its Segments Left field is not zero.
 *
 * @location: if the packet has nonzero segments left, the offset
 *		of the segments left field (from the start of @hdr6) will be
 *		stored here.
 */
static bool has_nonzero_segments_left(struct ipv6hdr const *hdr6,
		__u32 *location)
{
	struct ipv6_rt_hdr const *rt_hdr;
	unsigned int offset;

	rt_hdr = hdr_iterator_find(hdr6, NEXTHDR_ROUTING);
	if (!rt_hdr)
		return false;

	if (rt_hdr->segments_left == 0)
		return false;

	offset = ((void *)rt_hdr) - (void *)hdr6;
	*location = offset + offsetof(struct ipv6_rt_hdr, segments_left);
	return true;
}

/**
 * Translates @state->in's IPv6 header into @state->out's IPv4 header.
 * Only used for external IPv6 headers. (ie. not enclosed in ICMP errors.)
 * RFC 7915 sections 5.1 and 5.1.1.
 */
int ttp64_ipv4_external(struct xlation *state)
{
	struct ipv6hdr const *hdr6;
	struct iphdr *hdr4;
	struct frag_hdr const *hdr_frag;
	__u32 nonzero_location;
	int error;

	hdr6 = pkt_ip6_hdr(&state->in);

	if (hdr6->hop_limit <= 1) {
		log_debug("Packet's hop limit <= 1.");
		return drop_icmp(state, ICMPV6_TIME_EXCEED, ICMPV6_EXC_HOPLIMIT,
				0);
	}
	if (has_nonzero_segments_left(hdr6, &nonzero_location)) {
		log_debug("Packet's segments left field is nonzero.");
		return drop_icmp(state, ICMPV6_PARAMPROB, ICMPV6_HDR_FIELD,
				nonzero_location);
	}

	hdr4 = pkt_ip4_hdr(&state->out);
	hdr_frag = pkt_frag_hdr(&state->in);

	hdr4->version = 4;
	hdr4->ihl = 5;
	hdr4->tos = xlat_tos(state->cfg, hdr6);
	hdr4->tot_len = cpu_to_be16(state->out.skb->len);
	/* id is set later; please scroll down. */
	hdr4->frag_off = xlat_frag_off(hdr_frag, state);
	hdr4->ttl = hdr6->hop_limit - 1;
	hdr4->protocol = state->out.l4_proto;
	/* ip4_hdr->check is set later; please scroll down. */

	error = siit64_addrs(state, &hdr4->saddr, &hdr4->daddr);
	if (error)
		return error;

	generate_ipv4_id(state, hdr4, hdr_frag);

	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	return 0;
}

/**
 * Same as ttp64_ipv4_external(), except only used on internal headers.
 */
static int ttp64_ipv4_internal(struct xlation *state)
{
	struct packet const *in = &state->in;
	struct packet *out = &state->out;
	struct ipv6hdr const *hdr6 = pkt_ip6_hdr(in);
	struct iphdr *hdr4 = pkt_ip4_hdr(out);
	struct frag_hdr const *hdr_frag = pkt_frag_hdr(in);
	int error;

	hdr4->version = 4;
	hdr4->ihl = 5;
	hdr4->tos = xlat_tos(state->cfg, hdr6);
	hdr4->tot_len = cpu_to_be16(get_tot_len_ipv6(in->skb) - pkt_hdrs_len(in)
			+ pkt_hdrs_len(out));
	hdr4->frag_off = xlat_frag_off(hdr_frag, state);
	hdr4->ttl = hdr6->hop_limit;
	hdr4->protocol = xlat_proto(hdr6);

	error = siit64_addrs(state, &hdr4->saddr, &hdr4->daddr);
	if (error)
		return error;

	generate_ipv4_id(state, hdr4, hdr_frag);

	hdr4->check = 0;
	hdr4->check = ip_fast_csum(hdr4, hdr4->ihl);

	return 0;
}

/**
 * One liner for creating the ICMPv4 header's MTU field.
 * Returns the smallest out of the three parameters.
 */
static __be16 minimum(unsigned int mtu1, unsigned int mtu2, unsigned int mtu3)
{
	return cpu_to_be16(min(mtu1, min(mtu2, mtu3)));
}

static int compute_mtu4(struct xlation const *state)
{
	/* Meant for unit tests. */
	static const unsigned int INFINITE = 0xffffffff;
	struct icmphdr *out_icmp;
	struct icmp6hdr const *in_icmp;
	struct net_device const *in_dev;
	struct dst_entry const *out_dst;
	unsigned int in_mtu;
	unsigned int out_mtu;

	out_icmp = pkt_icmp4_hdr(&state->out);
	in_icmp = pkt_icmp6_hdr(&state->in);
	in_dev = state->in.skb->dev;
	in_mtu = in_dev ? in_dev->mtu : INFINITE;
	out_dst = skb_dst(state->out.skb);
	out_mtu = out_dst ? dst_mtu(out_dst) : INFINITE;

	log_debug("Packet MTU: %u", be32_to_cpu(in_icmp->icmp6_mtu));
	log_debug("In dev MTU: %u", in_mtu);
	log_debug("Out dev MTU: %u", out_mtu);

	out_icmp->un.frag.mtu = minimum(be32_to_cpu(in_icmp->icmp6_mtu) - 20,
			out_mtu,
			in_mtu - 20);
	log_debug("Resulting MTU: %u", be16_to_cpu(out_icmp->un.frag.mtu));

	return 0;
}

/**
 * One liner for translating the ICMPv6's pointer field to ICMPv4.
 * "Pointer" is a field from "Parameter Problem" ICMP messages.
 */
static int icmp6_to_icmp4_param_prob_ptr(struct xlation *state)
{
	struct icmp6hdr const *icmpv6_hdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->out);
	__u32 icmp6_ptr = be32_to_cpu(icmpv6_hdr->icmp6_dataun.un_data32[0]);
	__u32 icmp4_ptr;

	if (icmp6_ptr < 0 || 39 < icmp6_ptr)
		goto failure;

	switch (icmp6_ptr) {
	case 0:
		icmp4_ptr = 0;
		goto success;
	case 1:
		icmp4_ptr = 1;
		goto success;
	case 2:
	case 3:
		goto failure;
	case 4:
	case 5:
		icmp4_ptr = 2;
		goto success;
	case 6:
		icmp4_ptr = 9;
		goto success;
	case 7:
		icmp4_ptr = 8;
		goto success;
	}

	if (icmp6_ptr >= 24) {
		icmp4_ptr = 16;
		goto success;
	}
	if (icmp6_ptr >= 8) {
		icmp4_ptr = 12;
		goto success;
	}

	/* The above ifs are supposed to cover all the possible values. */
	WARN(true, "Parameter problem pointer '%u' is unknown.", icmp6_ptr);
	goto failure;

success:
	icmpv4_hdr->icmp4_unused = cpu_to_be32(icmp4_ptr << 24);
	return 0;
failure:
	log_debug("Parameter problem pointer '%u' lacks an ICMPv4 counterpart.",
			icmp6_ptr);
	return drop(state);
}

/**
 * One-liner for translating "Parameter Problem" messages from ICMPv6 to ICMPv4.
 */
static int icmp6_to_icmp4_param_prob(struct xlation *state)
{
	struct icmp6hdr const *icmpv6_hdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *icmpv4_hdr = pkt_icmp4_hdr(&state->out);

	switch (icmpv6_hdr->icmp6_code) {
	case ICMPV6_HDR_FIELD:
		return icmp6_to_icmp4_param_prob_ptr(state);

	case ICMPV6_UNK_NEXTHDR:
		icmpv4_hdr->icmp4_unused = 0;
		return 0;
	}

	/* Dead code */
	WARN(1, "ICMPv6 Parameter Problem code %u was unhandled by the switch above.",
			icmpv6_hdr->icmp6_type);
	return drop(state);
}

/*
 * Use this when only the ICMP header changed, so all there is to do is subtract
 * the old data from the checksum and add the new one.
 */
static void update_icmp4_csum(struct xlation const *state)
{
	struct ipv6hdr const *in_ip6 = pkt_ip6_hdr(&state->in);
	struct icmp6hdr const *in_icmp = pkt_icmp6_hdr(&state->in);
	struct icmphdr *out_icmp = pkt_icmp4_hdr(&state->out);
	struct icmp6hdr copy_hdr;
	__wsum csum, tmp;

	csum = ~csum_unfold(in_icmp->icmp6_cksum);

	/* Remove the ICMPv6 pseudo-header. */
	tmp = ~csum_unfold(csum_ipv6_magic(&in_ip6->saddr, &in_ip6->daddr,
			pkt_datagram_len(&state->in), NEXTHDR_ICMP, 0));
	csum = csum_sub(csum, tmp);

	/*
	 * Remove the ICMPv6 header.
	 * I'm working on a copy because I need to zero out its checksum.
	 * If I did that directly on the skb, I'd need to make it writable
	 * first.
	 */
	memcpy(&copy_hdr, in_icmp, sizeof(*in_icmp));
	copy_hdr.icmp6_cksum = 0;
	tmp = csum_partial(&copy_hdr, sizeof(copy_hdr), 0);
	csum = csum_sub(csum, tmp);

	/* Add the ICMPv4 header. There's no ICMPv4 pseudo-header. */
	out_icmp->checksum = 0;
	tmp = csum_partial(out_icmp, sizeof(*out_icmp), 0);
	csum = csum_add(csum, tmp);

	out_icmp->checksum = csum_fold(csum);
}

static int validate_icmp6_csum(struct xlation *state)
{
	struct packet const *in = &state->in;
	struct ipv6hdr const *hdr6;
	unsigned int len;
	__sum16 csum;

	if (in->skb->ip_summed != CHECKSUM_NONE)
		return 0;

	hdr6 = pkt_ip6_hdr(in);
	len = pkt_datagram_len(in);
	csum = csum_ipv6_magic(&hdr6->saddr, &hdr6->daddr, len, NEXTHDR_ICMP,
			skb_checksum(in->skb, skb_transport_offset(in->skb),
					len, 0));
	if (csum != 0) {
		log_debug("Checksum doesn't match.");
		return drop(state);
	}

	return 0;
}

static void update_total_length(struct packet const *out)
{
	struct iphdr *hdr;
	unsigned int new_len;

	hdr = pkt_ip4_hdr(out);
	new_len = out->skb->len;

	if (be16_to_cpu(hdr->tot_len) == new_len)
		return;

	hdr->tot_len = cpu_to_be16(new_len);
	hdr->frag_off &= cpu_to_be16(~IP_DF); /* Assumes new_len <= 1260 */
	hdr->check = 0;
	hdr->check = ip_fast_csum(hdr, hdr->ihl);
}

static int handle_icmp4_extension(struct xlation *state)
{
	struct icmpext_args args;
	struct packet *out;
	int error;

	args.max_pkt_len = 576;
	args.ipl = pkt_icmp6_hdr(&state->in)->icmp6_length << 3;
	args.out_bits = 2;
	args.force_remove_ie = false;

	error = handle_icmp_extension(state, &args);
	if (error)
		return error;

	out = &state->out;
	icmp4_length(pkt_icmp4_hdr(out)) = args.ipl;
	update_total_length(out);
	return 0;
}

/*
 * According to my tests, if we send an ICMP error that exceeds the MTU, Linux
 * will either drop it (if skb->local_df is false) or fragment it (if
 * skb->local_df is true).
 * Neither of these possibilities is even remotely acceptable.
 * We'll maximize delivery probability by truncating to mandatory minimum size.
 */
static int trim_576(struct xlation *state)
{
	struct packet *out;
	int error;

	out = &state->out;
	if (out->skb->len <= 576)
		return 0;

	error = pskb_trim(out->skb, 576);
	if (error) {
		log_debug("pskb_trim() error: %d", error);
		return drop(state);
	}

	update_total_length(out);
	return 0;
}

static int post_icmp4error(struct xlation *state, bool handle_extensions)
{
	static const struct translation_steps xsteps = {
		.xlat_l3 = ttp64_ipv4_internal,
		.xlat_tcp = ttp64_tcp,
		.xlat_udp = ttp64_udp,
		.xlat_icmp = ttp64_icmp,
	};
	int error;

	log_debug("Translating the inner packet (6->4)...");

	error = validate_icmp6_csum(state);
	if (error)
		return error;

	error = ttpcomm_translate_inner_packet(state, &xsteps);
	if (error)
		return error;

	if (handle_extensions) {
		error = handle_icmp4_extension(state);
		if (error)
			return error;
	}

	error = trim_576(state);
	if (error)
		return error;

	compute_icmp4_csum(state->out.skb);
	return 0;
}

static int echo(struct xlation *state, struct icmp6hdr const *icmp6,
		struct icmphdr *icmp4, __u8 type)
{
	icmp4->type = type;
	icmp4->code = 0;
	icmp4->un.echo.id = icmp6->icmp6_identifier;
	icmp4->un.echo.sequence = icmp6->icmp6_sequence;
	update_icmp4_csum(state);
	return 0;
}

/**
 * Translates in's icmp6 header and payload into out's icmp4 header and payload.
 * This is the core of RFC 7915 sections 5.2 and 5.3, except checksum (See
 * post_icmp4*()).
 */
int ttp64_icmp(struct xlation *state)
{
	struct icmp6hdr const *inhdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *outhdr = pkt_icmp4_hdr(&state->out);
	int error;

	outhdr->checksum = inhdr->icmp6_cksum; /* Updated later */

	switch (inhdr->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		return echo(state, inhdr, outhdr, ICMP_ECHO);
	case ICMPV6_ECHO_REPLY:
		return echo(state, inhdr, outhdr, ICMP_ECHOREPLY);

	case ICMPV6_DEST_UNREACH:
		outhdr->type = ICMP_DEST_UNREACH;
		switch (inhdr->icmp6_code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_NOT_NEIGHBOUR:
		case ICMPV6_ADDR_UNREACH:
			outhdr->code = ICMP_HOST_UNREACH;
			break;
		case ICMPV6_ADM_PROHIBITED:
			outhdr->code = ICMP_HOST_ANO;
			break;
		case ICMPV6_PORT_UNREACH:
			outhdr->code = ICMP_PORT_UNREACH;
			break;
		default:
			goto fail;
		}
		outhdr->icmp4_unused = 0;
		return post_icmp4error(state, true);

	case ICMPV6_TIME_EXCEED:
		outhdr->type = ICMP_TIME_EXCEEDED;
		outhdr->code = inhdr->icmp6_code;
		outhdr->icmp4_unused = 0;
		return post_icmp4error(state, true);

	case ICMPV6_PKT_TOOBIG:
		/*
		 * BTW, I have no idea what the RFC means by "taking into
		 * account whether or not the packet in error includes a
		 * Fragment Header"... What does the fragment header have to do
		 * with anything here?
		 */
		outhdr->type = ICMP_DEST_UNREACH;
		outhdr->code = ICMP_FRAG_NEEDED;
		outhdr->un.frag.__unused = 0;
		error = compute_mtu4(state);
		if (error)
			return error;
		return post_icmp4error(state, false);

	case ICMPV6_PARAMPROB:
		switch (inhdr->icmp6_code) {
		case ICMPV6_HDR_FIELD:
			outhdr->type = ICMP_PARAMETERPROB;
			outhdr->code = 0;
			break;
		case ICMPV6_UNK_NEXTHDR:
			outhdr->type = ICMP_DEST_UNREACH;
			outhdr->code = ICMP_PROT_UNREACH;
			break;
		default:
			goto fail;
		}
		error = icmp6_to_icmp4_param_prob(state);
		if (error)
			return error;
		return post_icmp4error(state, false);
	}

fail:
	/*
	 * The following codes are known to fall through here:
	 * ICMPV6_MGM_QUERY, ICMPV6_MGM_REPORT, ICMPV6_MGM_REDUCTION, Neighbor
	 * Discover messages (133 - 137).
	 */
	log_debug("ICMPv6 messages type %u code %u lack an ICMPv4 counterpart.",
			inhdr->icmp6_type, inhdr->icmp6_code);
	return drop(state);
}

static __wsum pseudohdr6_csum(struct ipv6hdr const *hdr)
{
	return ~csum_unfold(csum_ipv6_magic(&hdr->saddr, &hdr->daddr, 0, 0, 0));
}

static __wsum pseudohdr4_csum(struct iphdr const *hdr)
{
	return csum_tcpudp_nofold(hdr->saddr, hdr->daddr, 0, 0, 0);
}

static __sum16 update_csum_6to4(__sum16 csum16,
		struct ipv6hdr const *in_ip6, void const *in_l4_hdr, size_t in_l4_hdr_len,
		struct iphdr const *out_ip4, void const *out_l4_hdr, size_t out_l4_hdr_len)
{
	__wsum csum;

	csum = ~csum_unfold(csum16);

	/*
	 * Regarding the pseudoheaders:
	 * The length is pretty hard to obtain if there's TCP and fragmentation,
	 * and whatever it is, it's not going to change. Therefore, instead of
	 * computing it only to cancel it out with itself later, simply sum
	 * (and substract) zero.
	 * Do the same with proto since we're feeling ballsy.
	 */

	/* Remove the IPv6 crap. */
	csum = csum_sub(csum, pseudohdr6_csum(in_ip6));
	csum = csum_sub(csum, csum_partial(in_l4_hdr, in_l4_hdr_len, 0));

	/* Add the IPv4 crap. */
	csum = csum_add(csum, pseudohdr4_csum(out_ip4));
	csum = csum_add(csum, csum_partial(out_l4_hdr, out_l4_hdr_len, 0));

	return csum_fold(csum);
}

int ttp64_tcp(struct xlation *state)
{
	struct packet const *in = &state->in;
	struct packet *out = &state->out;
	struct tcphdr const *tcp_in = pkt_tcp_hdr(in);
	struct tcphdr *tcp_out = pkt_tcp_hdr(out);
	struct tcphdr tcp_copy;

	/* Header */
	memcpy(tcp_out, tcp_in, pkt_l4hdr_len(in));

	/* Header.checksum */
	if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
		memcpy(&tcp_copy, tcp_in, sizeof(*tcp_in));
		tcp_copy.check = 0;

		tcp_out->check = 0;
		tcp_out->check = update_csum_6to4(tcp_in->check,
				pkt_ip6_hdr(in), &tcp_copy, sizeof(tcp_copy),
				pkt_ip4_hdr(out), tcp_out, sizeof(*tcp_out));
		out->skb->ip_summed = CHECKSUM_NONE;

	} else {
		tcp_out->check = ~tcp_v4_check(pkt_datagram_len(out),
				pkt_ip4_hdr(out)->saddr,
				pkt_ip4_hdr(out)->daddr, 0);
		partialize_skb(out->skb, offsetof(struct tcphdr, check));
	}

	return 0;
}

int ttp64_udp(struct xlation *state)
{
	struct packet const *in = &state->in;
	struct packet *out = &state->out;
	struct udphdr const *udp_in = pkt_udp_hdr(in);
	struct udphdr *udp_out = pkt_udp_hdr(out);
	struct udphdr udp_copy;

	/* Header */
	memcpy(udp_out, udp_in, pkt_l4hdr_len(in));

	/* Header.checksum */
	if (in->skb->ip_summed != CHECKSUM_PARTIAL) {
		memcpy(&udp_copy, udp_in, sizeof(*udp_in));
		udp_copy.check = 0;

		udp_out->check = 0;
		udp_out->check = update_csum_6to4(udp_in->check,
				pkt_ip6_hdr(in), &udp_copy, sizeof(udp_copy),
				pkt_ip4_hdr(out), udp_out, sizeof(*udp_out));
		if (udp_out->check == 0)
			udp_out->check = CSUM_MANGLED_0;
		out->skb->ip_summed = CHECKSUM_NONE;

	} else {
		udp_out->check = ~udp_v4_check(pkt_datagram_len(out),
				pkt_ip4_hdr(out)->saddr,
				pkt_ip4_hdr(out)->daddr, 0);
		partialize_skb(out->skb, offsetof(struct udphdr, check));
	}

	return 0;
}

/*
 * TODO Maaaaaaaaybe replace this with icmp6_send().
 * I'm afraid of using such a high level function from here, tbh.
 */
void ttp64_icmp_err(struct xlation *state)
{
	struct sk_buff *skb, *out;
	struct ipv6hdr *hdr;
	struct ipv6hdr *iph;
	struct net *net;
	struct icmp6hdr *ich;
	int addr_type = 0;
	int len;
	__u8 type;
	__u8 code;
	bool allow;

	net = state->ns;
	skb = state->in.skb;
	hdr = ipv6_hdr(skb);
	type = state->result.type;
	code = state->result.code;
	/*
	 *	Make sure we respect the rules
	 *	i.e. RFC 1885 2.4(e)
	 *	Rule (e.1) is enforced by not using icmp6_send
	 *	in any code that processes icmp errors.
	 */

//	if (ipv6_chk_addr(net, &hdr->daddr, skb->dev, 0) ||
//	    ipv6_chk_acast_addr_src(net, skb->dev, &hdr->daddr))
//		saddr = &hdr->daddr;

	/*
	 *	Dest addr check
	 */

	addr_type = ipv6_addr_type(&hdr->daddr);
	if ((addr_type & IPV6_ADDR_MULTICAST) || skb->pkt_type != PACKET_HOST) {
		if (type != ICMPV6_PKT_TOOBIG &&
		    !(type == ICMPV6_PARAMPROB &&
		      code == ICMPV6_UNK_OPTION /* &&
		      (opt_unrec(skb, info)) */ ))
			return;
	}


	/*
	 *	Must not send error if the source does not uniquely
	 *	identify a single node (RFC2463 Section 2.4).
	 *	We check unspecified / multicast addresses here,
	 *	and anycast addresses will be checked later.
	 */
	addr_type = ipv6_addr_type(&hdr->saddr);
	if ((addr_type == IPV6_ADDR_ANY) || (addr_type & IPV6_ADDR_MULTICAST)) {
		net_dbg_ratelimited("icmp6_send: addr_any/mcast source [%pI6c > %pI6c]\n",
				    &hdr->saddr, &hdr->daddr);
		return;
	}

	/*
	 *	Never answer to a ICMP packet.
	 */
//	if (is_ineligible(skb)) {
//		net_dbg_ratelimited("icmp6_send: no reply to icmp error [%pI6c > %pI6c]\n",
//				    &hdr->saddr, &hdr->daddr);
//		return;
//	}

	/* Needed by both icmp_global_allow and icmpv6_xmit_lock */
	local_bh_disable();

	/* Check global sysctl_icmp_msgs_per_sec ratelimit */
//	if (!icmpv6_global_allow(net, type))
//		goto out_bh_enable;
	allow = icmp_global_allow();
	local_bh_enable();
	if (!allow)
		return;

	len = skb->len;
	if (len > 1280u)
		len = 1280u;

	out = netdev_alloc_skb(state->dev, LL_MAX_HEADER + len);
	if (!out)
		return;

	skb_reserve(out, LL_MAX_HEADER);
	skb_put(out, len);
	skb_reset_mac_header(out);
	skb_reset_network_header(out);
	skb_set_transport_header(out, sizeof(struct ipv6hdr));

	iph = ipv6_hdr(out);
	iph->version = 6;
	iph->priority = 0;
	iph->flow_lbl[0] = 0;
	iph->flow_lbl[1] = 0;
	iph->flow_lbl[2] = 0;
	iph->payload_len = htons(len - sizeof(*iph));
	iph->nexthdr = NEXTHDR_ICMP;
	iph->hop_limit = 255;

	/* FIXME variabilize */
	iph->saddr.s6_addr32[0] = htonl(0x20010db8);
	iph->saddr.s6_addr32[1] = htonl(0x01c00002);
	iph->saddr.s6_addr32[2] = htonl(0x00010000);
	iph->saddr.s6_addr32[3] = 0;

	iph->daddr = hdr->saddr;

	ich = icmp6_hdr(out);
	ich->icmp6_type = state->result.type;
	ich->icmp6_code = state->result.code;
	/* checksum later */
	ich->icmp6_unused = htonl(state->result.info);

	if (skb_copy_bits(skb, 0, ich + 1, len - sizeof(*iph) - sizeof(*ich))) {
		dev_kfree_skb(out);
		return;
	}

	compute_icmp6_csum(out);
	out->mark = IP6_REPLY_MARK(net, skb->mark);
	out->protocol = htons(ETH_P_IPV6);

	memset(&state->out, 0, sizeof(state->out));
	state->out.skb = out;
}
