#ifndef SRC_MOD_COMMON_RFC7915_6TO4_H_
#define SRC_MOD_COMMON_RFC7915_6TO4_H_

/**
 * RFC 7915 sections 5.1, 5.1.1, 5.2 and 5.3.
 * Not to be confused with the technology called "6to4", which is RFC 3056.
 */

#include "translation_state.h"

int ttp64_alloc_skb(struct xlation *state);
int ttp64_ipv4_external(struct xlation *state);
int ttp64_tcp(struct xlation *state);
int ttp64_udp(struct xlation *state);
int ttp64_icmp(struct xlation *state);
void ttp64_icmp_err(struct xlation *state);

#endif /* SRC_MOD_COMMON_RFC7915_6TO4_H_ */
