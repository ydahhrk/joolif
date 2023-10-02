#ifndef SRC_MOD_COMMON_LOG_H_
#define SRC_MOD_COMMON_LOG_H_

#include <linux/printk.h>

#define log_debug(text, ...) pr_info("joolif: " text "\n", ##__VA_ARGS__)

/**
 * These should not be committed, so if you see one in uploaded code, delete it.
 */
#define log_delete(text, ...) pr_err("DELETE ME! %s(%d): " text "\n", \
		__func__, __LINE__, ##__VA_ARGS__)
#define PR_DEBUG pr_err("%s:%d (%s())\n", __FILE__, __LINE__, __func__)

#endif /* SRC_MOD_COMMON_LOG_H_ */
