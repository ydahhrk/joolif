#include "address.h"
#include "log.h"

static inline bool prefix6_contains(const struct ipv6_prefix *prefix,
				    const struct in6_addr *addr)
{
	return ipv6_prefix_equal(&prefix->addr, addr, prefix->len);
}

static __be32 addr64(struct in6_addr const *src, unsigned int q1,
		     unsigned int q2, unsigned int q3, unsigned int q4)
{
	q1 = src->s6_addr[q1];
	q2 = src->s6_addr[q2];
	q3 = src->s6_addr[q3];
	q4 = src->s6_addr[q4];
	return htonl((q1 << 24) | (q2 << 16) | (q3 << 8) | q4);
}

static int rfc6052_6to4(struct ipv6_prefix const *prefix,
			struct in6_addr const *src, __be32 *dst)
{
	if (!prefix6_contains(prefix, src)) {
		log_debug("%pI6c/%u does not contain %pI6c.",
			  &prefix->addr, prefix->len, src);
		return -EINVAL;
	}

	switch (prefix->len) {
	case 96:
		*dst = src->s6_addr32[3];
		return 0;
	case 64:
		*dst = addr64(src, 9, 10, 11, 12);
		return 0;
	case 56:
		*dst = addr64(src, 7, 9, 10, 11);
		return 0;
	case 48:
		*dst = addr64(src, 6, 7, 9, 10);
		return 0;
	case 40:
		*dst = addr64(src, 5, 6, 7, 9);
		return 0;
	case 32:
		*dst = src->s6_addr32[1];
		return 0;
	}

	WARN(1, "Prefix has an invalid length: %u.", prefix->len);
	return -EINVAL;
}

static void addr46(__be32 __src, struct in6_addr *dst, unsigned int q1,
		   unsigned int q2, unsigned int q3, unsigned int q4)
{
	__u32 src = ntohl(__src);
	dst->s6_addr[q1] = ((src >> 24) & 0xFF);
	dst->s6_addr[q2] = ((src >> 16) & 0xFF);
	dst->s6_addr[q3] = ((src >>  8) & 0xFF);
	dst->s6_addr[q4] = ((src      ) & 0xFF);
}

int rfc6052_4to6(struct ipv6_prefix const *prefix, __be32 src,
			struct in6_addr *dst)
{
	memset(dst, 0, sizeof(*dst));

	switch (prefix->len) {
	case 96:
		dst->s6_addr32[0] = prefix->addr.s6_addr32[0];
		dst->s6_addr32[1] = prefix->addr.s6_addr32[1];
		dst->s6_addr32[2] = prefix->addr.s6_addr32[2];
		dst->s6_addr32[3] = src;
		return 0;
	case 64:
		dst->s6_addr32[0] = prefix->addr.s6_addr32[0];
		dst->s6_addr32[1] = prefix->addr.s6_addr32[1];
		addr46(src, dst, 9, 10, 11, 12);
		return 0;
	case 56:
		dst->s6_addr32[0] = prefix->addr.s6_addr32[0];
		dst->s6_addr[4] = prefix->addr.s6_addr[4];
		dst->s6_addr[5] = prefix->addr.s6_addr[5];
		dst->s6_addr[6] = prefix->addr.s6_addr[6];
		addr46(src, dst, 7, 9, 10, 11);
		return 0;
	case 48:
		dst->s6_addr32[0] = prefix->addr.s6_addr32[0];
		dst->s6_addr[4] = prefix->addr.s6_addr[4];
		dst->s6_addr[5] = prefix->addr.s6_addr[5];
		addr46(src, dst, 6, 7, 9, 10);
		return 0;
	case 40:
		dst->s6_addr32[0] = prefix->addr.s6_addr32[0];
		dst->s6_addr[4] = prefix->addr.s6_addr[4];
		addr46(src, dst, 5, 6, 7, 9);
		return 0;
	case 32:
		dst->s6_addr32[0] = prefix->addr.s6_addr32[0];
		dst->s6_addr32[1] = src;
		return 0;
	}

	/*
	 * Critical because enforcing valid prefixes is pool6's
	 * responsibility, not ours.
	 */
	WARN(1, "Prefix has an invalid length: %u.", prefix->len);
	return -EINVAL;
}

int siit64_addrs(struct xlation *state, __be32 *src, __be32 *dst)
{
	struct ipv6_prefix *pool6 = &state->cfg->pool6;
	struct ipv6hdr *hdr6 = pkt_ip6_hdr(&state->in);

	if (rfc6052_6to4(pool6, &hdr6->saddr, src) != 0) {
		if (!pkt_is_icmp6_error(&state->in))
			return drop(state);
		*src = state->cfg->pool6791v4.s_addr;
	}

	if (rfc6052_6to4(pool6, &hdr6->daddr, dst) != 0)
		return drop(state);

	log_debug("Result: %pI4->%pI4", src, dst);
	return 0;
}

int siit46_addrs(struct xlation *state, struct in6_addr *src,
		 struct in6_addr *dst)
{
	struct ipv6_prefix *pool6 = &state->cfg->pool6;
	struct iphdr *hdr4 = pkt_ip4_hdr(&state->in);

	if (rfc6052_4to6(pool6, hdr4->saddr, src) != 0)
		return drop(state);

	if (rfc6052_4to6(pool6, hdr4->daddr, dst) != 0)
		return drop(state);

	log_debug("Result: %pI6c->%pI6c", src, dst);
	return 0;
}
