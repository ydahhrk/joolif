#include "rfc7915.h"

#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/version.h>

#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/addrconf.h>

#include "aux.h"
#include "log.h"
#include "address.h"
#include "ipv6_hdr_iterator.h"
#include "packet.h"
#include "translation_state.h"
#include "types.h"

#define L3V6_HDRS_LEN (sizeof(struct ipv6hdr) + sizeof(struct frag_hdr))

/*
 * Allocates outgoing packet, copies dst_entry and layer 4 payload into it,
 * ensures there's enough headroom (bytes between skb->head and skb->data) for
 * translated headers. (In other words, it does everything except for headers.)
 */
typedef int (*pkt_init_fn)(struct xlation *, struct sk_buff *);
typedef int (*skb_alloc_fn)(struct xlation *);
typedef int (*hdr_xlat_fn)(struct xlation *);
typedef void (*icmp_error)(struct xlation *);

struct translation_steps {
	pkt_init_fn pkt_init;
	skb_alloc_fn skb_alloc;
	/* The function that will translate the IP header. */
	hdr_xlat_fn xlat_l3;
	/*
	 * Translates everything between the external IP header and the L4
	 * payload.
	 */
	hdr_xlat_fn xlat_tcp;
	hdr_xlat_fn xlat_udp;
	hdr_xlat_fn xlat_icmp;

	icmp_error icmp_err;
};

struct bkp_skb {
	unsigned int pulled;
	struct {
		int l3;
		int l4;
	} offset;
	unsigned int payload;
	__u8 l4_proto;
};

struct bkp_skb_tuple {
	struct bkp_skb in;
	struct bkp_skb out;
};

/* ICMP Extensions */

/* See /test/graybox/test-suite/siit/7915/README.md#ic */
struct icmpext_args {
	size_t max_pkt_len; /* Maximum (allowed outgoing) Packet Length */
	size_t ipl; /* Internal Packet Length */
	size_t out_bits; /* 4->6: Set as 3; 6->4: Set as 2 */
	bool force_remove_ie; /* Force removal of ICMP Extension? */
};

/*
 * Note: Fragmentation offloading is handled transparently: NIC joins fragments,
 * we translate the large and seemingly unfragmented packet, then NIC fragments
 * again, re-adding the fragment header.
 *
 * Same happens with defrag: Defrag defrags, Jool translates seemingly
 * unfragmented, enfrag enfrags.
 *
 * This function only returns true when WE are supposed to worry about the
 * fragment header. (ie. we're translating a completely unmanhandled fragment.)
 */
static bool will_need_frag_hdr(const struct iphdr *hdr)
{
	return ip_is_fragment(hdr);
}

static int move_pointers_in(struct packet *pkt, __u8 protocol,
			    unsigned int l3hdr_len)
{
	unsigned int l4hdr_len;

	if (!jskb_pull(pkt->skb, pkt_hdrs_len(pkt)))
		return -EINVAL;
	skb_reset_network_header(pkt->skb);
	skb_set_transport_header(pkt->skb, l3hdr_len);
	pkt->l4_proto = protocol;

	switch (protocol) {
	case IPPROTO_TCP:
		l4hdr_len = tcp_hdr_len(pkt_tcp_hdr(pkt));
		break;
	case IPPROTO_UDP:
		l4hdr_len = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		l4hdr_len = sizeof(struct icmphdr);
		break;
	case NEXTHDR_ICMP:
		l4hdr_len = sizeof(struct icmp6hdr);
		break;
	default:
		l4hdr_len = 0;
		break;
	}
	pkt->is_inner = true;
	pkt->payload_offset = skb_transport_offset(pkt->skb) + l4hdr_len;

	return 0;
}

static int move_pointers_out(struct packet *in, struct packet *out,
			     unsigned int l3hdr_len)
{
	if (!jskb_pull(out->skb, pkt_hdrs_len(out)))
		return -EINVAL;
	skb_reset_network_header(out->skb);
	skb_set_transport_header(out->skb, l3hdr_len);

	out->l4_proto = in->l4_proto;
	out->is_inner = true;
	out->payload_offset = skb_transport_offset(out->skb) + pkt_l4hdr_len(in);

	return 0;
}

static int move_pointers4(struct packet *in, struct packet *out, bool do_out)
{
	struct iphdr *hdr4;
	unsigned int l3hdr_len;
	int error;

	hdr4 = pkt_payload(in);
	error = move_pointers_in(in, hdr4->protocol, 4 * hdr4->ihl);
	if (error)
		return error;

	if (!do_out)
		return 0;

	l3hdr_len = sizeof(struct ipv6hdr);
	if (will_need_frag_hdr(hdr4))
		l3hdr_len += sizeof(struct frag_hdr);
	return move_pointers_out(in, out, l3hdr_len);
}

static int move_pointers6(struct packet *in, struct packet *out, bool do_out)
{
	struct ipv6hdr *hdr6 = pkt_payload(in);
	struct hdr_iterator iterator = HDR_ITERATOR_INIT(hdr6);
	int error;

	hdr_iterator_last(&iterator);

	error = move_pointers_in(in, iterator.hdr_type,
				 iterator.data - (void *)hdr6);
	if (error)
		return error;

	return do_out ? move_pointers_out(in, out, sizeof(struct iphdr)) : 0;
}

static void backup_pointers(struct packet *pkt, struct bkp_skb *bkp)
{
	bkp->pulled = pkt_hdrs_len(pkt);
	bkp->offset.l3 = skb_network_offset(pkt->skb);
	bkp->offset.l4 = skb_transport_offset(pkt->skb);
	bkp->payload = pkt->payload_offset;
	bkp->l4_proto = pkt->l4_proto;
}

static void restore_pointers(struct packet *pkt, struct bkp_skb *bkp)
{
	skb_push(pkt->skb, bkp->pulled);
	skb_set_network_header(pkt->skb, bkp->offset.l3);
	skb_set_transport_header(pkt->skb, bkp->offset.l4);
	pkt->payload_offset = bkp->payload;
	pkt->l4_proto = bkp->l4_proto;
	pkt->is_inner = 0;
}

static int become_inner_packet(struct xlation *state, struct bkp_skb_tuple *bkp,
			       bool do_out)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;

	backup_pointers(in, &bkp->in);
	if (do_out)
		backup_pointers(out, &bkp->out);

	switch (in->l3_proto) {
	case PF_INET:
		if (move_pointers4(in, out, do_out))
			return drop(state);
		break;
	case PF_INET6:
		if (move_pointers6(in, out, do_out))
			return drop(state);
		break;
	}

	return 0;
}

static void restore_outer_packet(struct xlation *state,
				 struct bkp_skb_tuple *bkp, bool do_out)
{
	restore_pointers(&state->in, &bkp->in);
	if (do_out)
		restore_pointers(&state->out, &bkp->out);
}

static int xlat_l4_function(struct xlation *state,
			    struct translation_steps const *steps)
{
	switch (state->in.l4_proto) {
	case IPPROTO_TCP:
		return steps->xlat_tcp(state);
	case IPPROTO_UDP:
		return steps->xlat_udp(state);
	case IPPROTO_ICMP:
	case NEXTHDR_ICMP:
		return steps->xlat_icmp(state);
	default:
		return 0; /* Hope for the best */
	}

	WARN(1, "Unknown l4 proto: %u", state->in.l4_proto);
	return drop(state);
}

static int ttpcomm_translate_inner_packet(struct xlation *state,
					  struct translation_steps const *steps)
{
	struct bkp_skb_tuple bkp;
	int error;

	error = become_inner_packet(state, &bkp, true);
	if (error)
		return error;

	error = steps->xlat_l3(state);
	if (error)
		goto end;

	error = xlat_l4_function(state, steps);

end:
	restore_outer_packet(state, &bkp, true);
	return error;
}

/*
 * partialize_skb - set up @out_skb so the layer 4 checksum will be computed
 * from almost-scratch by the OS or by the NIC later.
 * @csum_offset: The checksum field's offset within its header.
 *
 * When the incoming skb's ip_summed field is NONE, UNNECESSARY or COMPLETE,
 * the checksum is defined, in the sense that its correctness consistently
 * dictates whether the packet is corrupted or not. In these cases, Jool is
 * supposed to update the checksum with the translation changes (pseudoheader
 * and transport header) and forget about it. The incoming packet's corruption
 * will still be reflected in the outgoing packet's checksum.
 *
 * On the other hand, when the incoming skb's ip_summed field is PARTIAL,
 * the existing checksum only covers the pseudoheader (which Jool replaces).
 * In these cases, fully updating the checksum is wrong because it doesn't
 * already cover the transport header, and fully computing it again is wasted
 * time because this work can be deferred to the NIC (which'll likely do it
 * faster).
 *
 * The correct thing to do is convert the partial (pseudoheader-only) checksum
 * into a translated-partial (pseudoheader-only) checksum, and set up some skb
 * fields so the NIC can do its thing.
 *
 * This function handles the skb fields setting part.
 */
static void partialize_skb(struct sk_buff *out_skb, __u16 csum_offset)
{
	out_skb->ip_summed = CHECKSUM_PARTIAL;
	out_skb->csum_start = skb_transport_header(out_skb) - out_skb->head;
	out_skb->csum_offset = csum_offset;
}

static int fix_ie(struct xlation *state, size_t in_ie_offset, size_t ipl,
		  size_t pad, size_t iel)
{
	struct sk_buff *skb_old;
	struct sk_buff *skb_new;
	unsigned int ohl; /* Outer Headers Length */
	void *beginning;
	void *to;
	int offset;
	int len;
	int error;

	skb_old = state->out.skb;
	ohl = pkt_hdrs_len(&state->out);
	len = ohl + ipl + pad + iel;
	skb_new = alloc_skb(LL_MAX_HEADER + len, GFP_ATOMIC);
	if (!skb_new)
		return drop(state);

	skb_reserve(skb_new, LL_MAX_HEADER);
	beginning = skb_put(skb_new, len);
	skb_reset_mac_header(skb_new);
	skb_reset_network_header(skb_new);
	skb_set_transport_header(skb_new, skb_transport_offset(skb_old));

	/* Outer headers */
	offset = skb_network_offset(skb_old);
	to = beginning;
	len = ohl;
	error = skb_copy_bits(skb_old, offset, to, len);
	if (error)
		goto copy_fail;

	/* Internal packet */
	offset += len;
	to += len; /* alloc_skb() always creates linear packets. */
	len = ipl;
	error = skb_copy_bits(skb_old, offset, to, len);
	if (error)
		goto copy_fail;

	if (iel) {
		/* Internal packet padding */
		to += len;
		len = pad;
		memset(to, 0, len);

		/* ICMP Extension */
		offset = in_ie_offset;
		to += len;
		len = iel;
		error = skb_copy_bits(state->in.skb, offset, to, len);
		if (error)
			goto copy_fail;
	}

	skb_dst_set(skb_new, dst_clone(skb_dst(skb_old)));
	kfree_skb(skb_old);
	state->out.skb = skb_new;
	return 0;

copy_fail:
	log_debug("skb_copy_bits(skb, %d, %zd, %d) threw error %d.",
		  offset, to - beginning, len, error);
	return drop(state);
}

/*
 * Use this when header and payload both changed completely, so we gotta just
 * trash the old checksum and start anew.
 */
static void compute_icmp4_csum(struct sk_buff *skb)
{
	struct icmphdr *hdr = icmp_hdr(skb);

	/*
	 * This function only gets called for ICMP error checksums, so
	 * skb_datagram_len() is fine.
	 */
	hdr->checksum = 0;
	hdr->checksum = csum_fold(skb_checksum(skb, skb_transport_offset(skb),
					       skb_datagram_len(skb), 0));
	skb->ip_summed = CHECKSUM_NONE;
}

static void compute_icmp6_csum(struct sk_buff *out)
{
	struct ipv6hdr *out_ip6 = ipv6_hdr(out);
	struct icmp6hdr *out_icmp = icmp6_hdr(out);
	__wsum csum;

	/*
	 * This function only gets called for ICMP error checksums, so
	 * pkt_datagram_len() is fine.
	 */
	out_icmp->icmp6_cksum = 0;
	csum = skb_checksum(out, skb_transport_offset(out),
			    skb_datagram_len(out), 0);
	out_icmp->icmp6_cksum = csum_ipv6_magic(&out_ip6->saddr,
						&out_ip6->daddr,
						skb_datagram_len(out),
						IPPROTO_ICMPV6, csum);
	out->ip_summed = CHECKSUM_NONE;
}

/*
 * "Handle the ICMP Extension" in this context means
 *
 * - Make sure it aligns in accordance with the target protocol's ICMP length
 *   field. (32 bits in IPv4, 64 bits in IPv6)
 * - Make sure it fits in the packet in accordance with the target protocol's
 *   official maximum ICMP error size. (576 for IPv4, 1280 for IPv6)
 * 	- If it doesn't fit, remove it completely.
 * 	- If it does fit, trim the Optional Part if needed.
 * - Add padding to the internal packet if necessary.
 *
 * Again, see /test/graybox/test-suite/siit/7915/README.md#ic.
 *
 * "Handle the ICMP Extension" does NOT mean:
 *
 * - Translate the contents. (Jool treats extensions like opaque bit strings.)
 * - Update outer packet's L3 checksums and lengths. (Too difficult to do here;
 *   caller's responsibility.) This includes the ICMP header length.
 *
 * If this function succeeds, it will return the value of the ICMP header length
 * in args->ipl.
 */
static int handle_icmp_extension(struct xlation *state,
				 struct icmpext_args *args)
{
	struct packet *in;
	struct packet *out;
	size_t payload_len; /* Incoming packet's payload length */
	size_t in_iel; /* Incoming packet's IE length */
	size_t max_iel; /* Maximum outgoing packet's allowable IE length */
	size_t in_ieo; /* Incoming packet's IE offset */
	size_t out_ipl; /* Outgoing packet's internal packet length */
	size_t out_pad; /* Outgoing packet's padding length */
	size_t out_iel; /* Outgoing packet's IE length */

	in = &state->in;
	out = &state->out;

	/* Validate input */
	if (args->ipl == 0)
		return 0;
	/*
	 * There used to be a validation here, dropping packets whose args->ipl
	 * was less than 128. RFC4884 requires the essential part of ICMP
	 * extension'd packets to length >= 128, but certain Internet routers
	 * break this rule, and this in turn breaks traceroutes.
	 * https://github.com/NICMx/Jool/issues/396
	 *
	 * Current implementation: Translate < 128 incorrect unpadded packets
	 * into 128 correct padded packets.
	 */

	payload_len = in->skb->len - pkt_hdrs_len(in);
	if (args->ipl == payload_len) {
		args->ipl = 0;
		return 0; /* Whatever, I guess */
	}
	if (args->ipl > payload_len) {
		log_debug("ICMP Length %zu > L3 payload %zu", args->ipl,
			  payload_len);
		return drop(state);
	}

	/* Compute helpers */
	in_ieo = pkt_hdrs_len(in) + args->ipl;
	in_iel = in->skb->len - in_ieo;
	max_iel = args->max_pkt_len - (pkt_hdrs_len(out) + 128);

	/* Figure out what we want to do */
	/* (Assumption: In packet's iel equals current out packet's iel) */
	if (args->force_remove_ie || (in_iel > max_iel)) {
		out_ipl = min(out->skb->len - in_iel, args->max_pkt_len) -
			  pkt_hdrs_len(out);
		out_pad = 0;
		out_iel = 0;
		args->ipl = 0;
	} else {
		out_ipl = min((size_t)out->skb->len, args->max_pkt_len) -
			  in_iel - pkt_hdrs_len(out);
		/* Note to self: Yes, truncate. It's already maximized;
		 * we can't add any zeroes. Just make it fit. */
		out_ipl &= (~(size_t)0) << args->out_bits;
		out_pad = (out_ipl < 128) ? (128 - out_ipl) : 0;
		out_iel = in_iel;
		args->ipl = (out_ipl + out_pad) >> args->out_bits;
	}

	/* Move everything around */
	return fix_ie(state, skb_network_offset(in->skb) + in_ieo, out_ipl,
		      out_pad, out_iel);
}

static void skb_cleanup_copy(struct sk_buff *skb)
{
	/* https://github.com/NICMx/Jool/issues/289 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	nf_reset_ct(skb);
#else
	nf_reset(skb);
#endif

	/* https://github.com/NICMx/Jool/issues/400 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	skb_clear_tstamp(skb);
#else
	skb->tstamp = 0;
#endif

//	skb_dst_drop(skb);
}

static __u8 proto2nexthdr(__u8 proto)
{
	return (proto == IPPROTO_ICMP) ? NEXTHDR_ICMP : proto;
}

static int iphdr_delta(struct iphdr *hdr)
{
	/* TODO check this returns proper negative */
	return sizeof(struct ipv6hdr) - (hdr->ihl << 2);
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
		hdr_frag = (struct frag_hdr *)(skb_network_header(out) +
					       sizeof(struct ipv6hdr));
		skb_set_transport_header(out, sizeof(struct ipv6hdr) +
					      sizeof(struct frag_hdr));
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
	unsigned int remainder; /* Payload not yet consumed */
	unsigned int capacity; /* Layer 3 payload we can fit in each fragment */
	unsigned int plen; /* Current fragment's layer 3 payload length */
	unsigned int offset; /* Payload bytes copied so far */
	struct frag_hdr *frag;
	unsigned char *l3_payload;

	in = &state->in;
	previous = &state->out.skb;
	remainder = in->skb->len - pkt_l3hdr_len(in);
	capacity = (mpl - L3V6_HDRS_LEN) & 0xFFFFFFF8U;
	offset = 0;

	while (remainder > 0) {
		if (remainder > capacity) {
			plen = capacity;
			remainder -= capacity;
		} else {
			plen = remainder;
			remainder = 0;
		}

		out = alloc_skb(skb_headroom(in->skb) + L3V6_HDRS_LEN + plen,
				GFP_ATOMIC);
		if (!out)
			goto fail;

		*previous = out;
		previous = &out->next;

		skb_reserve(out, skb_headroom(in->skb));
		skb_reset_mac_header(out);
		skb_reset_network_header(out);
		skb_put(out, sizeof(struct ipv6hdr));
		frag = (struct frag_hdr *)skb_put(out, sizeof(struct frag_hdr));
		l3_payload = skb_put(out, plen);

		skb_set_transport_header(out, L3V6_HDRS_LEN);
		if (out == state->out.skb) {
			pkt_fill(&state->out, out, PF_INET6,
				 proto2nexthdr(in->l4_proto), frag,
				 l3_payload + pkt_l4hdr_len(in));
		}

		out->ignore_df = false;
		out->mark = in->skb->mark;
		out->protocol = htons(ETH_P_IPV6);

		if (skb_copy_bits(in->skb,
				  skb_transport_offset(in->skb) + offset,
				  l3_payload, plen))
			goto fail;
		offset += plen;
	}

	return 0;

fail:
	kfree_skb_list(state->out.skb);
	state->out.skb = NULL;
	return drop(state);
}

static int ttp46_alloc_skb(struct xlation *state)
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
	 * TODO this needs to be simplified now that we're not in Netfilter.
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
		 * ICMP error means the fragment header will never be added,
		 * so Fast Path is always viable.
		 */
		return allocate_fast(state, false, 0);
	}

	out_len = fragment_exceeds_mtu46(in);

	if (is_df_set(pkt_ip4_hdr(in))) {
		/*
		 * Good; sender is smart.
		 * Fragment header will only be included if already fragmented.
		 */
		if (out_len > nexthop_mtu) {
			log_debug("IPv6 packet size %u > nexthop MTU %u.",
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

/*
 * Returns true if hdr contains a source route option and the last address
 * from it hasn't been reached.
 *
 * Assumes the options are pullable.
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

/*
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
	frag_offset = get_v6_frag_offset(frag) + first->len - L3V6_HDRS_LEN;
	first_mf = is_mf_set_ipv6(frag);
	frag->frag_off |= cpu_to_be16(IP6_MF);

	for (skb = first->next; skb != NULL; skb = skb->next) {
		hdr6 = ipv6_hdr(skb);
		frag = (struct frag_hdr *)(hdr6 + 1);

		memcpy(hdr6, ipv6_hdr(first), L3V6_HDRS_LEN);
		hdr6->payload_len = cpu_to_be16(skb->len - sizeof(*hdr6));
		frag->frag_off = build_v6_frag_offset(frag_offset,
						      skb->next ? 1 : first_mf);

		frag_offset += skb->len - L3V6_HDRS_LEN;
	}
}

static int ttcp46_ipv6_common(struct xlation *state)
{
	struct packet *in = &state->in;
	struct packet *out = &state->out;
	struct iphdr *hdr4 = pkt_ip4_hdr(in);
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(out);
	struct frag_hdr *hdrf;
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
		hdrf = (struct frag_hdr *)(hdr6 + 1);
		hdrf->nexthdr = hdr6->nexthdr;
		hdr6->nexthdr = NEXTHDR_FRAGMENT;
		hdrf->reserved = 0;
		hdrf->frag_off = build_v6_frag_offset(get_v4_frag_offset(hdr4),
						      is_mf_set_ipv4(hdr4));
		hdrf->identification = build_id_field(hdr4);
	}

	return 0;
}

/* RFC 7915, section 4.1. */
static int ttp46_ipv6_external(struct xlation *state)
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
	hdr6->payload_len = cpu_to_be16(be16_to_cpu(pkt_ip4_hdr(in)->tot_len) -
					pkt_hdrs_len(in) + pkt_hdrs_len(out) -
					sizeof(struct ipv6hdr));

	return ttcp46_ipv6_common(state);
}

/*
 * One liner for creating the ICMPv6 header's MTU field.
 * Returns the smallest out of the three first parameters. It also handles some
 * quirks. See comments inside for more info.
 */
static __be32 icmp6_min_mtu(struct xlation *state, unsigned int pkt_mtu,
			    unsigned int nexthop6mtu, unsigned int nexthop4mtu,
			    __u16 tot_len_field)
{
	__u32 result;

	if (pkt_mtu == 0) {
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
				pkt_mtu = plateaus[i];
				break;
			}
		}
	}

	/* Here's the core comparison. */
	result = min(pkt_mtu + 20, min(nexthop6mtu, nexthop4mtu + 20));
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
	out_icmp->icmp6_mtu = icmp6_min_mtu(state,
					    be16_to_cpu(in_icmp->un.frag.mtu),
					    out_mtu, in_mtu,
					    be16_to_cpu(hdr4->tot_len));
	log_debug("Resulting MTU: %u", be32_to_cpu(out_icmp->icmp6_mtu));

	return 0;
}

/*
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
	WARN(1, "Unhandled ICMPv4 Destination Unreachable code %u.",
	     icmp4_hdr->code);
	return drop(state);
}

/*
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
			log_debug("Untranslatable: "
				  "ICMPv4 type %u code %u pointer %u.",
				  icmp4_hdr->type, icmp4_hdr->code, ptr);
			return drop(state);
		}

		icmp6_hdr->icmp6_pointer = cpu_to_be32(ptrs[ptr]);
		return 0;
	}

	/* Dead code */
	WARN(1, "Unhandled ICMPv4 Parameter Problem %u.", icmp4_hdr->code);
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
						&out_ip6->daddr,
						pkt_datagram_len(&state->in),
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
	pkt_ip6_hdr(out)->payload_len = cpu_to_be16(out->skb->len -
						    sizeof(struct ipv6hdr));
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

	pkt_ip6_hdr(out)->payload_len = cpu_to_be16(out->skb->len -
						    sizeof(struct ipv6hdr));
	return 0;
}

static int ttp46_tcp(struct xlation *state);
static int ttp46_udp(struct xlation *state);
static int ttp46_icmp(struct xlation *state);

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

static int ttp46_echo(struct xlation *state, struct icmphdr const *icmp4,
		      struct icmp6hdr *icmp6, __u8 type)
{
	icmp6->icmp6_type = type;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_identifier = icmp4->un.echo.id;
	icmp6->icmp6_sequence = icmp4->un.echo.sequence;
	update_icmp6_csum(state);
	return 0;
}

/*
 * Translates in's icmp4 header and payload into out's icmp6 header and payload.
 * This is the RFC 7915 sections 4.2 and 4.3, except checksum (See post_icmp6()).
 */
static int ttp46_icmp(struct xlation *state)
{
	struct icmphdr *inhdr = pkt_icmp4_hdr(&state->in);
	struct icmp6hdr *outhdr = pkt_icmp6_hdr(&state->out);
	int error;

	outhdr->icmp6_cksum = inhdr->checksum; /* Updated later */

	/* -- First the ICMP header. -- */
	switch (inhdr->type) {
	case ICMP_ECHO:
		return ttp46_echo(state, inhdr, outhdr, ICMPV6_ECHO_REQUEST);
	case ICMP_ECHOREPLY:
		return ttp46_echo(state, inhdr, outhdr, ICMPV6_ECHO_REPLY);

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
	log_debug("Untranslatable: ICMPv4 type %u code %u.",
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

/*
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
						      &out_ip6->daddr,
						      0, 0, 0));
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

static int ttp46_tcp(struct xlation *state)
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

static int ttp46_udp(struct xlation *state)
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
static void ttp46_icmp_err(struct xlation *state)
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

	log_debug("Sending ICMPv4 error.");

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
	iph->frag_off = build_v4_frag_offset(1, 0, 0);
	iph->ttl = 64; /* FIXME Probably change to 255 */
	iph->protocol = IPPROTO_ICMP;
	iph->saddr = state->cfg->pool6791v4.s_addr;
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

static __u8 xlat_tos(struct jool_globals const *cfg, struct ipv6hdr const *hdr)
{
	return cfg->reset_tos ? cfg->new_tos : get_traffic_class(hdr);
}

static __u8 nexthdr2proto(__u8 nexthdr)
{
	return (nexthdr == NEXTHDR_ICMP) ? IPPROTO_ICMP : nexthdr;
}

/*
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

static int ttp64_alloc_skb(struct xlation *state)
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

/*
 * One-liner for creating the IPv4 header's Identification field.
 *
 * Note, because of __ip_select_ident(), the following fields need to be already
 * set: hdr4->saddr, hdr4->daddr, hdr4->protocol.
 */
static void generate_ipv4_id(struct xlation const *state, struct iphdr *hdr4,
			     struct frag_hdr const *hdr_frag)
{
	if (hdr_frag)
		hdr4->id = cpu_to_be16(be32_to_cpu(hdr_frag->identification));
	else
		__ip_select_ident(state->ns, hdr4, 1);
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
		frag_offset = get_v6_frag_offset(hdr_frag);
	} else {
		df = generate_df_flag(state);
		mf = 0;
		frag_offset = 0;
	}

	return build_v4_frag_offset(df, mf, frag_offset);
}

/*
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

/*
 * Translates @state->in's IPv6 header into @state->out's IPv4 header.
 * Only used for external IPv6 headers. (ie. not enclosed in ICMP errors.)
 * RFC 7915 sections 5.1 and 5.1.1.
 */
static int ttp64_ipv4_external(struct xlation *state)
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

/*
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
	hdr4->tot_len = cpu_to_be16(get_tot_len_ipv6(in->skb) -
				    pkt_hdrs_len(in) +
				    pkt_hdrs_len(out));
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

/*
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
					out_mtu, in_mtu - 20);
	log_debug("Resulting MTU: %u", be16_to_cpu(out_icmp->un.frag.mtu));

	return 0;
}

/*
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

/*
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
	WARN(1, "Unhandled ICMPv6 Parameter Problem code %u.",
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
			       skb_checksum(in->skb,
					    skb_transport_offset(in->skb),
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

static int ttp64_tcp(struct xlation *state);
static int ttp64_udp(struct xlation *state);
static int ttp64_icmp(struct xlation *state);

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

static int ttp64_echo(struct xlation *state, struct icmp6hdr const *icmp6,
		      struct icmphdr *icmp4, __u8 type)
{
	icmp4->type = type;
	icmp4->code = 0;
	icmp4->un.echo.id = icmp6->icmp6_identifier;
	icmp4->un.echo.sequence = icmp6->icmp6_sequence;
	update_icmp4_csum(state);
	return 0;
}

/*
 * Translates in's icmp6 header and payload into out's icmp4 header and payload.
 * This is the core of RFC 7915 sections 5.2 and 5.3, except checksum (See
 * post_icmp4*()).
 */
static int ttp64_icmp(struct xlation *state)
{
	struct icmp6hdr const *inhdr = pkt_icmp6_hdr(&state->in);
	struct icmphdr *outhdr = pkt_icmp4_hdr(&state->out);
	int error;

	outhdr->checksum = inhdr->icmp6_cksum; /* Updated later */

	switch (inhdr->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		return ttp64_echo(state, inhdr, outhdr, ICMP_ECHO);
	case ICMPV6_ECHO_REPLY:
		return ttp64_echo(state, inhdr, outhdr, ICMP_ECHOREPLY);

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
	log_debug("Untranslatable: ICMPv6 type %u code %u .",
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
				struct ipv6hdr const *in_ip6,
				void const *in_l4_hdr,
				size_t in_l4_hdr_len,
				struct iphdr const *out_ip4,
				void const *out_l4_hdr,
				size_t out_l4_hdr_len)
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

static int ttp64_tcp(struct xlation *state)
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
						  pkt_ip6_hdr(in), &tcp_copy,
						  sizeof(tcp_copy),
						  pkt_ip4_hdr(out),
						  tcp_out, sizeof(*tcp_out));
		out->skb->ip_summed = CHECKSUM_NONE;

	} else {
		tcp_out->check = ~tcp_v4_check(pkt_datagram_len(out),
					       pkt_ip4_hdr(out)->saddr,
					       pkt_ip4_hdr(out)->daddr, 0);
		partialize_skb(out->skb, offsetof(struct tcphdr, check));
	}

	return 0;
}

static int ttp64_udp(struct xlation *state)
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
						  pkt_ip6_hdr(in), &udp_copy,
						  sizeof(udp_copy),
						  pkt_ip4_hdr(out), udp_out,
						  sizeof(*udp_out));
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

static int
xlat_icmperr_saddr(struct xlation *state, struct in6_addr *saddr)
{
	struct in6_addr *p = &state->cfg->pool6791v6;

	if (p->s6_addr32[0] != 0 ||
	    p->s6_addr32[1] != 0 ||
	    p->s6_addr32[2] != 0 ||
	    p->s6_addr32[3] != 0) {
		*saddr = *p;
		return 0;
	}

	return rfc6052_4to6(&state->cfg->pool6, state->cfg->pool6791v4.s_addr,
			    saddr);
}

/*
 * TODO Maaaaaaaaybe replace this with icmp6_send().
 * I'm afraid of using such a high level function from here, tbh.
 */
static void ttp64_icmp_err(struct xlation *state)
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

	log_debug("Sending ICMPv6 error.");

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

	len = sizeof(*iph) + sizeof(*ich) + skb->len;
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
	iph->hop_limit = 64; /* FIXME Probably change to 255 */
	if (xlat_icmperr_saddr(state, &iph->saddr) != 0) {
		dev_kfree_skb(out);
		return;
	}
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
	out->mark = skb->mark; /* IP6_REPLY_MARK(net, skb->mark); */
	out->protocol = htons(ETH_P_IPV6);

	memset(&state->out, 0, sizeof(state->out));
	state->out.skb = out;
}

static const struct translation_steps steps64 = {
	.pkt_init = pkt_init_ipv6,
	.skb_alloc = ttp64_alloc_skb,
	.xlat_l3 = ttp64_ipv4_external,
	.xlat_tcp = ttp64_tcp,
	.xlat_udp = ttp64_udp,
	.xlat_icmp = ttp64_icmp,
	.icmp_err = ttp64_icmp_err,
};

static const struct translation_steps steps46 = {
	.pkt_init = pkt_init_ipv4,
	.skb_alloc = ttp46_alloc_skb,
	.xlat_l3 = ttp46_ipv6_external,
	.xlat_tcp = ttp46_tcp,
	.xlat_udp = ttp46_udp,
	.xlat_icmp = ttp46_icmp,
	.icmp_err = ttp46_icmp_err,
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

	switch (ntohs(in->protocol)) {
	case ETH_P_IPV6:
		steps = &steps64;
		break;
	case ETH_P_IP:
		steps = &steps46;
		break;
	default:
		log_debug("Unsupported l3 proto: %u", ntohs(in->protocol));
		drop(state);
		return;
	}

	if (steps->pkt_init(state, in) != 0)
		goto fail;
	if (steps->skb_alloc(state) != 0)
		goto fail;
	if (steps->xlat_l3(state) != 0)
		goto fail;
	if (has_l4_hdr(state) && (xlat_l4_function(state, steps) != 0))
		goto fail;
	return;

fail:
	kfree_skb_list(state->out.skb);
	state->out.skb = NULL;

	if (state->result.set)
		steps->icmp_err(state);
}
