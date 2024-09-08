#include "packet.h"

#include <linux/icmp.h>
#include <net/route.h>

#include "types.h"
#include "log.h"
#include "translation_state.h"

/*
 * Note: Offsets need to be relative to skb->data because that's how
 * skb_header_pointer() works.
 */
struct pkt_metadata {
	/*
	 * "Offset of the Fragment Header."
	 *
	 * Offset is from skb->data. Zero if there's no fragment header.
	 * Note, having a fragment header does not imply that the packet is
	 * fragmented.
	 */
	unsigned int fhdr_offset;
	/* Actual packet protocol; not tuple protocol. */
	__u8 l4_proto;
	/* Offset is from skb->data. */
	unsigned int l4_offset;
	/* Offset is from skb->data. */
	unsigned int payload_offset;
};

#define skb_hdr_ptr(skb, offset, buffer) \
	skb_header_pointer(skb, offset, sizeof(buffer), &buffer)

static bool has_inner_pkt4(__u8 icmp_type)
{
	return icmp_is_err(icmp_type);
}

static bool has_inner_pkt6(__u8 icmp6_type)
{
	return icmpv6_is_err(icmp6_type);
}

/* It seems that this should never trigger ICMP errors. */
static int truncated(struct xlation *state, const char *what)
{
	log_debug("The %s seems truncated.", what);
	return drop(state);
}

/*
 * This is relevant because we need to call pskb_may_pull(), which might
 * eventually call pskb_expand_head(), and that panics if the packet is shared.
 * Therefore, I think this validation (with messy WARN included) is fair.
 */
static int fail_if_shared(struct xlation *state)
{
	if (WARN(skb_shared(state->in.skb), "The packet is shared!"))
		return drop(state);

	/*
	 * Keep in mind... "shared" and "cloned" are different concepts.
	 * We know the sk_buff struct is unique, but somebody else might have an
	 * active pointer towards the data area.
	 */
	return 0;
}

/*
 * Jool doesn't like making assumptions, but it certainly needs to make a few.
 * One of them is that the skb_network_offset() offset is meant to be relative
 * to skb->data. Thing is, this should be part of the contract of the function,
 * but I don't see it set in stone anywhere. (Not even in the "How skbs work"
 * guide.)
 *
 * Now, it's pretty obvious that this is the case for all such skbuff.h
 * non-paged offsets at present, but I'm keeping my buttcheeks tight in case
 * they are meant to be relative to a common pivot rather than a specific one.
 */
static int fail_if_broken_offset(struct xlation *state)
{
	struct sk_buff *skb = state->in.skb;

	if (WARN(skb_network_offset(skb) != (skb_network_header(skb) - skb->data),
		 "The packet's network header offset is not relative to skb->data.\n"
		 "Translating this packet would break Jool, so dropping."))
		return drop(state);

	return 0;
}

static int paranoid_validations(struct xlation *state, size_t min_hdr_size)
{
	int error;

	error = fail_if_shared(state);
	if (error)
		return error;
	error = fail_if_broken_offset(state);
	if (error)
		return error;
	if (!pskb_may_pull(state->in.skb, min_hdr_size))
		return truncated(state, "basic IP header");

	return 0;
}

/*
 * Walks through @skb's headers, collecting data and adding it to @meta.
 *
 * @hdr6_offset number of bytes between skb->data and the IPv6 header.
 *
 * BTW: You might want to read summarize_skb4() first, since it's a lot simpler.
 */
static int summarize_skb6(struct xlation *state, unsigned int hdr6_offset,
			  struct pkt_metadata *meta)
{
	union {
		struct ipv6_opt_hdr opt;
		struct frag_hdr frag;
		struct tcphdr tcp;
	} buffer;
	union {
		struct ipv6_opt_hdr *opt;
		struct frag_hdr *frag;
		struct tcphdr *tcp;
		u8 *nexthdr;
	} ptr;

	struct sk_buff *skb = state->in.skb;
	u8 nexthdr;
	unsigned int offset;
	bool is_first = true;

	ptr.nexthdr = skb_hdr_ptr(skb,
				  hdr6_offset + offsetof(struct ipv6hdr, nexthdr),
				  nexthdr);
	if (!ptr.nexthdr)
		return truncated(state, "IPv6 header");
	nexthdr = *ptr.nexthdr;
	offset = hdr6_offset + sizeof(struct ipv6hdr);

	meta->fhdr_offset = 0;

	do {
		switch (nexthdr) {
		case NEXTHDR_TCP:
			meta->l4_proto = NEXTHDR_TCP;
			meta->l4_offset = offset;
			meta->payload_offset = offset;

			if (is_first) {
				ptr.tcp = skb_hdr_ptr(skb, offset, buffer.tcp);
				if (!ptr.tcp)
					return truncated(state, "TCP header");
				meta->payload_offset += tcp_hdr_len(ptr.tcp);
			}

			return 0;

		case NEXTHDR_UDP:
			meta->l4_proto = NEXTHDR_UDP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first
					     ? (offset + sizeof(struct udphdr))
					     : offset;
			return 0;

		case NEXTHDR_ICMP:
			meta->l4_proto = NEXTHDR_ICMP;
			meta->l4_offset = offset;
			meta->payload_offset = is_first
					     ? (offset + sizeof(struct icmp6hdr))
					     : offset;
			return 0;

		case NEXTHDR_FRAGMENT:
			if (meta->fhdr_offset) {
				log_debug("Double fragment header.");
				return drop(state);
			}

			ptr.frag = skb_hdr_ptr(skb, offset, buffer.frag);
			if (!ptr.frag)
				return truncated(state, "fragment header");

			meta->fhdr_offset = offset;
			is_first = is_first_frag6(ptr.frag);

			offset += sizeof(struct frag_hdr);
			nexthdr = ptr.frag->nexthdr;
			break;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_DEST:
			if (meta->fhdr_offset) {
				log_debug("There's a known extension header (%u) after Fragment.",
					  nexthdr);
				return drop_icmp(state, ICMPV6_DEST_UNREACH,
						 ICMPV6_ADM_PROHIBITED, 0);
			}

			ptr.opt = skb_hdr_ptr(skb, offset, buffer.opt);
			if (!ptr.opt)
				return truncated(state, "extension header");

			offset += ipv6_optlen(ptr.opt);
			nexthdr = ptr.opt->nexthdr;
			break;

		default:
			meta->l4_proto = nexthdr;
			meta->l4_offset = offset;
			meta->payload_offset = offset;
			return 0;
		}
	} while (true);

	return 0; /* whatever. */
}

static int validate_inner6(struct xlation *state,
			   struct pkt_metadata const *outer_meta)
{
	union {
		struct ipv6hdr ip6;
		struct frag_hdr frag;
		struct icmp6hdr icmp;
	} buffer;
	union {
		struct ipv6hdr *ip6;
		struct frag_hdr *frag;
		struct icmp6hdr *icmp;
	} ptr;

	struct pkt_metadata meta;
	int error;

	ptr.ip6 = skb_hdr_ptr(state->in.skb, outer_meta->payload_offset,
			      buffer.ip6);
	if (!ptr.ip6)
		return truncated(state, "inner IPv6 header");
	if (unlikely(ptr.ip6->version != 6)) {
		log_debug("Version is not 6.");
		return drop(state);
	}

	error = summarize_skb6(state, outer_meta->payload_offset, &meta);
	if (error)
		return error;

	if (meta.fhdr_offset) {
		ptr.frag = skb_hdr_ptr(state->in.skb, meta.fhdr_offset,
				       buffer.frag);
		if (!ptr.frag)
			return truncated(state, "inner fragment header");
		if (!is_first_frag6(ptr.frag)) {
			log_debug("Inner packet is not a first fragment.");
			return drop(state);
		}
	}

	if (meta.l4_proto == NEXTHDR_ICMP) {
		ptr.icmp = skb_hdr_ptr(state->in.skb, meta.l4_offset,
				       buffer.icmp);
		if (!ptr.icmp)
			return truncated(state, "inner ICMPv6 header");
		if (has_inner_pkt6(ptr.icmp->icmp6_type)) {
			log_debug("Packet inside packet inside packet.");
			return drop(state);
		}
	}

	if (!pskb_may_pull(state->in.skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return truncated(state, "inner headers");
	}

	return 0;
}

static int handle_icmp6(struct xlation *state, struct pkt_metadata const *meta)
{
	union {
		struct icmp6hdr icmp;
		struct frag_hdr frag;
	} buffer;
	union {
		struct icmp6hdr *icmp;
		struct frag_hdr *frag;
	} ptr;

	/* See handle_icmp4() comment */
	if (meta->fhdr_offset) {
		ptr.frag = skb_hdr_ptr(state->in.skb, meta->fhdr_offset,
				       buffer.frag);
		if (!ptr.frag)
			return truncated(state, "fragment header");
		if (ip6_is_fragment(ptr.frag)) {
			log_debug("Packet is fragmented and ICMP; ICMP checksum cannot be translated.");
			return drop(state);
		}
	}

	ptr.icmp = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer.icmp);
	if (!ptr.icmp)
		return truncated(state, "ICMPv6 header");

	return has_inner_pkt6(ptr.icmp->icmp6_type)
	     ? validate_inner6(state, meta)
	     : 0;
}

int pkt_init_ipv6(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	state->in.skb = skb;

	/*
	 * DO NOT, UNDER ANY CIRCUMSTANCES, EXTRACT ANY BYTES FROM THE SKB'S
	 * DATA AREA DIRECTLY (ie. without using skb_hdr_ptr()) UNTIL YOU KNOW
	 * IT HAS ALREADY BEEN pskb_may_pull()ED. ASSUME THAT EVEN THE MAIN
	 * LAYER 3 HEADER CAN BE PAGED.
	 *
	 * Also, careful in this function and subfunctions. pskb_may_pull()
	 * might change pointers, so you generally don't want to store them.
	 */

	error = paranoid_validations(state, sizeof(struct ipv6hdr));
	if (error)
		return error;

	log_debug("Packet: %pI6c->%pI6c", &ipv6_hdr(skb)->saddr,
		  &ipv6_hdr(skb)->daddr);

	if (skb->len != get_tot_len_ipv6(skb)) {
		log_debug("Packet size doesn't match the IPv6 header's payload length field.");
		return drop(state);
	}

	error = summarize_skb6(state, skb_network_offset(skb), &meta);
	if (error)
		return error;

	if (meta.l4_proto == NEXTHDR_ICMP) {
		/* Do not move this to summarize_skb6(), because it risks infinite recursion. */
		error = handle_icmp6(state, &meta);
		if (error)
			return error;
	}

	if (!pskb_may_pull(skb, meta.payload_offset))
		return truncated(state, "headers");

	state->in.l3_proto = PF_INET6;
	state->in.l4_proto = meta.l4_proto;
	state->in.is_inner = 0;
	state->in.frag_offset = meta.fhdr_offset;
	skb_set_transport_header(skb, meta.l4_offset);
	state->in.payload_offset = meta.payload_offset;

	return 0;
}

static int validate_inner4(struct xlation *state, struct pkt_metadata *meta)
{
	union {
		struct iphdr ip4;
		struct tcphdr tcp;
	} buffer;
	union {
		struct iphdr *ip4;
		struct tcphdr *tcp;
	} ptr;
	unsigned int ihl;
	unsigned int offset = meta->payload_offset;

	ptr.ip4 = skb_hdr_ptr(state->in.skb, offset, buffer.ip4);
	if (!ptr.ip4)
		return truncated(state, "inner IPv4 header");

	ihl = ptr.ip4->ihl << 2;
	if (ptr.ip4->version != 4) {
		log_debug("Inner packet is not IPv4.");
		return drop(state);
	}
	if (ihl < 20) {
		log_debug("Inner packet's IHL is bogus.");
		return drop(state);
	}
	if (ntohs(ptr.ip4->tot_len) < ihl) {
		log_debug("Inner packet's total length is bogus.");
		return drop(state);
	}
	if (!is_first_frag4(ptr.ip4)) {
		log_debug("Inner packet is not first fragment.");
		return drop(state);
	}

	offset += ihl;

	switch (ptr.ip4->protocol) {
	case IPPROTO_TCP:
		ptr.tcp = skb_hdr_ptr(state->in.skb, offset, buffer.tcp);
		if (!ptr.tcp)
			return truncated(state, "inner TCP header");
		offset += tcp_hdr_len(ptr.tcp);
		break;
	case IPPROTO_UDP:
		offset += sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		offset += sizeof(struct icmphdr);
		break;
	}

	if (!pskb_may_pull(state->in.skb, offset))
		return truncated(state, "inner headers");

	return 0;
}

static int handle_icmp4(struct xlation *state, struct pkt_metadata *meta)
{
	struct icmphdr buffer, *ptr;

	/*
	 * If fragmented:
	 * 	If ICMP error:
	 * 		Drop (because illegal)
	 * 	Else (ie. ICMP info):
	 * 		Drop (because csum cannot be translated)
	 *
	 * In short: Don't ever allow fragmented ICMP.
	 */
	if (ip_is_fragment(pkt_ip4_hdr(&state->in))) {
		log_debug("Packet is fragmented and ICMP; ICMP checksum cannot be translated.");
		return drop(state);
	}

	ptr = skb_hdr_ptr(state->in.skb, meta->l4_offset, buffer);
	if (!ptr)
		return truncated(state, "ICMP header");

	return has_inner_pkt4(ptr->type) ? validate_inner4(state, meta) : 0;
}

static int summarize_skb4(struct xlation *state, struct pkt_metadata *meta)
{
	struct iphdr *hdr4 = ip_hdr(state->in.skb);
	unsigned int offset;

	hdr4 = ip_hdr(state->in.skb);
	offset = skb_network_offset(state->in.skb) + (hdr4->ihl << 2);

	meta->fhdr_offset = 0;
	meta->l4_offset = offset;
	meta->payload_offset = offset;
	meta->l4_proto = hdr4->protocol;

	switch (hdr4->protocol) {
	case IPPROTO_TCP:
		if (is_first_frag4(hdr4)) {
			struct tcphdr buffer, *ptr;
			ptr = skb_hdr_ptr(state->in.skb, offset, buffer);
			if (!ptr)
				return truncated(state, "TCP header");
			meta->payload_offset += tcp_hdr_len(ptr);
		}
		return 0;

	case IPPROTO_UDP:
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct udphdr);
		return 0;

	case IPPROTO_ICMP:
		if (is_first_frag4(hdr4))
			meta->payload_offset += sizeof(struct icmphdr);
		return handle_icmp4(state, meta);
	}

	return 0;
}

int pkt_init_ipv4(struct xlation *state, struct sk_buff *skb)
{
	struct pkt_metadata meta;
	int error;

	state->in.skb = skb;

	/*
	 * DO NOT, UNDER ANY CIRCUMSTANCES, EXTRACT ANY BYTES FROM THE SKB'S
	 * DATA AREA DIRECTLY (ie. without using skb_hdr_ptr()) UNTIL YOU KNOW
	 * IT HAS ALREADY BEEN pskb_may_pull()ED. ASSUME THAT EVEN THE MAIN
	 * LAYER 3 HEADER CAN BE PAGED.
	 *
	 * Also, careful in this function and subfunctions. pskb_may_pull()
	 * might change pointers, so you generally don't want to store them.
	 */

	error = paranoid_validations(state, sizeof(struct iphdr));
	if (error)
		return error;

	log_debug("Packet: %pI4->%pI4",
		  &ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr);

	error = summarize_skb4(state, &meta);
	if (error)
		return error;

	if (!pskb_may_pull(skb, meta.payload_offset)) {
		log_debug("Could not 'pull' the headers out of the skb.");
		return truncated(state, "headers");
	}

	state->in.l3_proto = PF_INET;
	state->in.l4_proto = meta.l4_proto;
	state->in.is_inner = false;
	state->in.frag_offset = 0;
	skb_set_transport_header(skb, meta.l4_offset);
	state->in.payload_offset = meta.payload_offset;

	return 0;
}

/*
 * skb_pull() is oddly special in that it can return NULL in a situation where
 * most skb functions would just panic. Which is actually great for skb_pull();
 * the kernel good practices thingy rightfully states that we should always
 * respond to such situations gracefully instead of BUG()ging out like a bunch
 * of wusses.
 *
 * These situations should not arise, however, so we should treat them as
 * programming errors. (WARN, cancel the packet's translation and then continue
 * normally.)
 *
 * This function takes care of the WARN clutter. "j" stands for "Jool", as
 * usual.
 *
 * Never use skb_pull() directly.
 *
 * TODO (fine) the 7915 code is breaking that rule.
 */
unsigned char *jskb_pull(struct sk_buff *skb, unsigned int len)
{
	unsigned char *result = skb_pull(skb, len);
	WARN(!result, "Bug: We tried to pull %u bytes out of a %u-length skb.",
	     len, skb->len);
	return result;
}
