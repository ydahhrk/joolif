#ifndef SRC_MOD_COMMON_TRANSLATION_STATE_H_
#define SRC_MOD_COMMON_TRANSLATION_STATE_H_

#include <uapi/linux/if_link.h>

#include "packet.h"

typedef enum icmp_errcode {
	ICMPERR_TTL,
	ICMPERR_FRAG_NEEDED,
	ICMPERR_HDR_FIELD,
	ICMPERR_SRC_ROUTE,
	ICMPERR_FILTER,
} icmp_error_code;

struct xlation_result {
	enum icmp_errcode icmp;
	__u32 info;
};

/**
 * State of the current translation.
 */
struct xlation {
	struct net *ns;

	struct jool_globals *cfg;
	struct rtnl_link_stats64 *stats;

	/** The original packet. */
	struct packet in;
	/** The translated version of @in. */
	struct packet out;

	struct xlation_result result;
};

int drop(struct xlation *state);
int drop_icmp(struct xlation *state, enum icmp_errcode icmp, __u32 info);

#endif /* SRC_MOD_COMMON_TRANSLATION_STATE_H_ */
