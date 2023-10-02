#ifndef SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_
#define SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_

/**
 * @file
 * Third step in the packet processing algorithm defined in the RFC.
 * The 3.6 section of RFC 6146 is encapsulated in this module.
 * Infers a tuple (summary) of the outgoing packet, yet to be created.
 */

#include "translation_state.h"

int rfc6052_4to6(struct ipv6_prefix const *prefix, __be32 src,
		struct in6_addr *dst);

int siit64_addrs(struct xlation *state, __be32 *src, __be32 *dst);
int siit46_addrs(struct xlation *state, struct in6_addr *src,
		 struct in6_addr *dst);

#endif /* SRC_MOD_NAT64_COMPUTE_OUTGOING_TUPLE_H_ */
