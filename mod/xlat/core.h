#ifndef SRC_MOD_COMMON_RFC7915_CORE_H_
#define SRC_MOD_COMMON_RFC7915_CORE_H_

/**
 * @file
 * This is the face of the "Translating the Packet" code. Files outside of this
 * folder should only see the API exposed by this file.
 *
 * "Translating the Packet" is the core translation of SIIT and the fourth step
 * of NAT64 (RFC6146 section 3.7).
 */

#include <linux/skbuff.h>

struct xlation;
void jool_xlat(struct xlation *state, struct sk_buff *in);

#endif /* SRC_MOD_COMMON_RFC7915_CORE_H_ */
