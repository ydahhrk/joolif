#include "types.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>

bool is_icmp6_error(__u8 type)
{
	return (type == ICMPV6_DEST_UNREACH) ||
	       (type == ICMPV6_PKT_TOOBIG) ||
	       (type == ICMPV6_TIME_EXCEED) ||
	       (type == ICMPV6_PARAMPROB);
}

bool is_icmp4_error(__u8 type)
{
	return (type == ICMP_DEST_UNREACH) ||
	       (type == ICMP_SOURCE_QUENCH) ||
	       (type == ICMP_REDIRECT) ||
	       (type == ICMP_TIME_EXCEEDED) ||
	       (type == ICMP_PARAMETERPROB);
}
