#ifndef MOD_XLAT_AUX_H_
#define MOD_XLAT_AUX_H_

/* Stuff that should maybe be added to linux/include/uapi/linux/icmp.h */

#define icmp4_unused		un.gateway
#define icmp4_datagram_length	un.reserved[1]

/* Code 0 for ICMP type ICMP_PARAMETERPROB */
#define ICMP_PTR_INDICATES_ERR	0
/* Code 2 for ICMP type ICMP_PARAMETERPROB */
#define ICMP_BAD_LENGTH		2

#endif /* MOD_XLAT_AUX_H_ */
