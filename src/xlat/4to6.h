#ifndef SRC_MOD_COMMON_RFC7915_4TO6_H_
#define SRC_MOD_COMMON_RFC7915_4TO6_H_

/* RFC 7915 sections 4.1, 4.2 and 4.3.  */

#include "translation_state.h"

int ttp46_alloc_skb(struct xlation *state);
int ttp46_ipv6_external(struct xlation *state);
int ttp46_tcp(struct xlation *state);
int ttp46_udp(struct xlation *state);
int ttp46_icmp(struct xlation *state);

#endif /* SRC_MOD_COMMON_RFC7915_4TO6_H_ */
