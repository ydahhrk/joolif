#ifndef SRC_MOD_COMMON_PACKET_H_
#define SRC_MOD_COMMON_PACKET_H_

/*
 * @file
 * Random packet-related functions.
 *
 * Relevant topics:
 *
 * # Packet Buffering
 *
 * GRO, nf_defrag_ipv6 and nf_defrag_ipv4 can merge a bunch of related packets
 * on input, by buffering them in `skb_shinfo(skb)->frags` or queuing them in
 * `skb_shinfo(skb)->frag_list`. Lots of kernel functions will try to fool you
 * into thinking they're a single packet.
 *
 * For the most part, this is fine. Unfortunately, individual fragment surgery
 * is sometimes necessary evil for PMTU reasons. Therefore, you need to
 * understand frags and frag_list if you're going to manipulate lengths (and
 * sometimes checksums).
 *
 * # Internal Packets
 *
 * Packets contained inside ICMP errors. A good chunk of the RFC7915 code is
 * reused by external and internal packets.
 *
 * They can be truncated. When this happens, their header lengths will
 * contradict their actual lengths. For this reason, in general, Jool should
 * rarely rely on header lengths.
 *
 * # Local Glossary
 *
 * - data payload area: Bytes that lie in an skb between skb->head and
 *   skb->tail, excluding headers.
 * - paged area: Bytes the skb stores in skb_shinfo(skb)->frags.
 * - frag_list area: Bytes the skb stores in skb_shinfo(skb)->frag_list,
 *   and *also* the bytes these fragments store in their own paged areas.
 *
 * These are all L4 payload only. The kernel deletes frags and frag_list headers
 * on input, then recreates them on output.
 *
 * - Subsequent fragment: Packet with fragment offset nonzero.
 *   (These only show up when nf_defrag_ipv* is disabled; ie. stateless
 *   translators only.)
 */

#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include "types.h"

static struct jool_cb *
JOOL_CB(struct sk_buff const *skb)
{
	return (struct jool_cb *)(skb->cb);
}

/* Returns a hack-free version of the 'Traffic class' field from @hdr. */
static inline __u8 get_traffic_class(struct ipv6hdr const *hdr)
{
	__u8 upper_bits = hdr->priority;
	__u8 lower_bits = hdr->flow_lbl[0] >> 4;
	return (upper_bits << 4) | lower_bits;
}

/* Returns IP_DF if the DF flag from @hdr is set, 0 otherwise. */
static inline __u16 is_df_set(struct iphdr const *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP_DF;
}

/* Returns IP6_MF if the MF flag from @hdr is set, 0 otherwise. */
static inline __u16 is_mf_set_ipv6(struct frag_hdr const *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP6_MF;
}

/* Returns IP_MF if the MF flag from @hdr is set, 0 otherwise. */
static inline __u16 is_mf_set_ipv4(struct iphdr const *hdr)
{
	return be16_to_cpu(hdr->frag_off) & IP_MF;
}

/* Returns a hack-free version of the 'Fragment offset' field from @hdr. */
static inline __u16 get_v6_frag_offset(struct frag_hdr const *hdr)
{
	return be16_to_cpu(hdr->frag_off) & 0xFFF8U;
}

/* Returns a hack-free version of the 'Fragment offset' field from @hdr. */
static inline __u16 get_v4_frag_offset(struct iphdr const *hdr)
{
	__u16 frag_off = be16_to_cpu(hdr->frag_off);
	/* 3 bit shifts to the left == multiplication by 8. */
	return (frag_off & IP_OFFSET) << 3;
}

/*
 * Pretends @skb's IPv6 header has a "total length" field and returns its value.
 */
static inline unsigned int get_tot_len_ipv6(struct sk_buff const *skb)
{
	return sizeof(struct ipv6hdr) + be16_to_cpu(ipv6_hdr(skb)->payload_len);
}

static inline bool is_first_frag4(struct iphdr const *hdr)
{
	return get_v4_frag_offset(hdr) == 0;
}

static inline bool is_first_frag6(struct frag_hdr const *hdr)
{
	return hdr ? (get_v6_frag_offset(hdr) == 0) : true;
}

static inline bool ip6_is_fragment(struct frag_hdr const *hdr)
{
	if (!hdr)
		return false;
	return (get_v6_frag_offset(hdr) != 0) || is_mf_set_ipv6(hdr);
}

/*
 * frag_hdr.frag_off is actually a combination of the 'More fragments' flag and
 * the 'Fragment offset' field. This function is a one-liner for creating a
 * settable frag_off.
 * Note that fragment offset is measured in units of eight-byte blocks. That
 * means that you want @frag_offset to be a multiple of 8 if you want your
 * fragmentation to work properly.
 */
static inline __be16 build_v6_frag_offset(__u16 frag_offset, __u16 mf)
{
	__u16 result = (frag_offset & 0xFFF8U) | (mf ? 1U : 0U);
	return cpu_to_be16(result);
}

/*
 * iphdr.frag_off is actually a combination of the DF flag, the MF flag and the
 * 'Fragment offset' field. This function is a one-liner for creating a settable
 * frag_off.
 * Note that fragment offset is measured in units of eight-byte blocks. That
 * means that you want @frag_offset to be a multiple of 8 if you want your
 * fragmentation to work properly.
 */
static inline __be16 build_v4_frag_offset(bool df, __u16 mf, __u16 frag_offset)
{
	__u16 result = (df ? (1U << 14) : 0) |
		       (mf ? (1U << 13) : 0) |
		       (frag_offset >> 3);
	return cpu_to_be16(result);
}

/*
 * Returns the size in bytes of @hdr, including options.
 * skbless variant of tcp_hdrlen().
 */
static inline unsigned int tcp_hdr_len(struct tcphdr const *hdr)
{
	return hdr->doff << 2;
}

struct jool_cb {
	__u8 l3_proto;
	__u8 l4_proto;
	/* Is this a subpacket, contained in an ICMP error? */
	bool is_inner;

	/* Offset of the skb's fragment header (from skb->data), if any. */
	unsigned int frag_offset;
	/*
	 * Offset of the packet's payload. (From skb->data.)
	 * Because skbs only store pointers to headers.
	 *
	 * Sometimes the kernel seems to use skb->data for this. It would be
	 * troublesome if we did the same, however, since functions such as
	 * icmp_send() fail early when skb->data is after the layer-3 header.
	 *
	 * Note, even after the packet is validated, the payload can be paged
	 * (unlike headers). Do not access the data pointed by this field
	 * carelessly.
	 */
	unsigned int payload_offset;
};

/*
 * Initializes @pkt using the rest of the arguments.
 */
static inline void pkt_fill(struct sk_buff *skb, __u8 l3_proto, __u8 l4_proto,
			    struct frag_hdr *frag, void *payload)
{
	struct jool_cb *cb = JOOL_CB(skb);

	cb->l3_proto = l3_proto;
	cb->l4_proto = l4_proto;
	cb->is_inner = 0;
	cb->frag_offset = frag ? ((unsigned char *)frag - skb->data) : 0;
	cb->payload_offset = (unsigned char *)payload - skb->data;
}

/* l3_proto must be IPv6. */
static inline struct frag_hdr *pkt_frag_hdr(struct sk_buff const *skb)
{
	unsigned int offset = JOOL_CB(skb)->frag_offset;
	return offset ? ((struct frag_hdr *)(skb->data + offset)) : NULL;
}

static inline void *pkt_payload(struct sk_buff const *skb)
{
	return skb->data + JOOL_CB(skb)->payload_offset;
}

static inline bool pkt_is_inner(struct sk_buff const *skb)
{
	return JOOL_CB(skb)->is_inner;
}

static inline bool pkt_is_outer(struct sk_buff const *skb)
{
	return !pkt_is_inner(skb);
}

static inline unsigned int skb_l3hdr_len(struct sk_buff const *skb)
{
	return skb_transport_header(skb) - skb_network_header(skb);
}

/* Includes first set of layer-4 headers (including options). */
static inline unsigned int pkt_l4hdr_len(struct sk_buff const *skb)
{
	return pkt_payload(skb) - (void *)skb_transport_header(skb);
}

/* Includes first set of layer-3 and layer-4 headers. */
static inline unsigned int pkt_hdrs_len(struct sk_buff const *skb)
{
	return JOOL_CB(skb)->payload_offset;
}

/*
 * Includes headroom payload (which itself includes l4 header), frag_list
 * payload and frags payload.
 */
static inline unsigned int skb_datagram_len(struct sk_buff const *skb)
{
	return skb->len - skb_l3hdr_len(skb);
}

static inline bool pkt_is_icmp6_error(struct sk_buff const *skb)
{
	return (JOOL_CB(skb)->l4_proto == NEXTHDR_ICMP) &&
	       icmpv6_is_err(icmp6_hdr(skb)->icmp6_type);
}

static inline bool pkt_is_icmp4_error(struct sk_buff const *skb)
{
	return (JOOL_CB(skb)->l4_proto == IPPROTO_ICMP) &&
	       icmp_is_err(icmp_hdr(skb)->type);
}

struct xlation; // XXX

/*
 * Ensures @skb isn't corrupted and initializes @state->in out of it.
 *
 * After this function, code can assume:
 * - @skb contains full l3 and l4 headers (including inner ones), their order
 *   seems to make sense, and they are all within the data area of @skb. (ie.
 *   they are not paged.)
 * - @skb's payload isn't truncated (though inner packet payload might).
 * - The pkt_* functions above can now be used on @state->in.
 * - The length fields in the l3 headers can be relied upon. (But not the ones
 *   contained in inner packets.)
 *
 * Healthy layer 4 checksums and lengths are not guaranteed, but that's not an
 * issue since this kind of corruption should be translated along (see
 * validate_icmp6_csum()).
 *
 * Also, this function does not ensure @skb is either TCP, UDP or ICMP. This is
 * because SIIT Jool must translate other protocols in a best-effort basis.
 *
 * This function can change the packet's pointers. If you eg. stored a pointer
 * to skb_network_header(skb), you will need to assign it again (by calling
 * skb_network_header() again).
 */
int pkt_init_ipv6(struct xlation *state, struct sk_buff *skb);
int pkt_init_ipv4(struct xlation *state, struct sk_buff *skb);
/*
 * @}
 */

unsigned char *jskb_pull(struct sk_buff *skb, unsigned int len);

#endif /* SRC_MOD_COMMON_PACKET_H_ */
