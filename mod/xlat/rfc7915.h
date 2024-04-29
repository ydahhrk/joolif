#ifndef MOD_XLAT_RFC7915_H_
#define MOD_XLAT_RFC7915_H_

#include <linux/skbuff.h>

struct xlation;
void jool_xlat(struct xlation *state, struct sk_buff *in);

#endif /* MOD_XLAT_RFC7915_H_ */
