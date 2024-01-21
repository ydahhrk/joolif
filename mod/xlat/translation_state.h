#ifndef SRC_MOD_COMMON_TRANSLATION_STATE_H_
#define SRC_MOD_COMMON_TRANSLATION_STATE_H_

#include <uapi/linux/if_link.h>

#include "packet.h"

struct xlation_result {
	__u8 set;
	__u8 type;
	__u8 code;
	__u32 info;
};

/**
 * State of the current translation.
 */
struct xlation {
	struct net *ns; /* TODO maybe not needed anymore? use dev instead */
	struct net_device *dev; /* Easy pointer for the Jool device. */

	struct jool_globals *cfg;

	/** The original packet. */
	struct packet in;
	/** The translated version of @in. */
	struct packet out;

	struct xlation_result result;
};

int drop(struct xlation *state);
int drop_icmp(struct xlation *state, __u8 type, __u8 code, __u32 info);

#endif /* SRC_MOD_COMMON_TRANSLATION_STATE_H_ */
