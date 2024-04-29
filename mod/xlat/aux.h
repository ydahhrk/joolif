#ifndef MOD_XLAT_AUX_H_
#define MOD_XLAT_AUX_H_

/* Stuff that should maybe be added to the kernel headers. */

/*
 * More generic accesor to the unused portion of the ICMP header as a __be32,
 * missing from uapi/linux/icmp.h
 */
#define icmp4_unused un.gateway

#define icmp6_length icmp6_dataun.un_data8[0]
/* un.reserved does not exist in old kernels. */
#define icmp4_length(hdr) (((__u8 *)(&(hdr)->un.gateway))[1])

/* Code 0 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_PTR_INDICATES_ERROR 0
/* Code 2 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_BAD_LENGTH 2

#endif /* MOD_XLAT_AUX_H_ */
