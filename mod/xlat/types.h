#ifndef SRC_MOD_COMMON_TYPES_H_
#define SRC_MOD_COMMON_TYPES_H_

/*
 * @file
 * Kernel-specific core data types and routines.
 */

#include <linux/netfilter.h>
#include <linux/kernel.h>

#define PLATEAUS_MAX 64

struct mtu_plateaus {
	__u16 values[PLATEAUS_MAX];
	/* Actual length of the values array. */
	__u16 count;
};

/*
 * The network component of a IPv6 address.
 */
struct ipv6_prefix {
	/* IPv6 prefix. The suffix is most of the time assumed to be zero. */
	struct in6_addr addr;
	/* Number of bits from "address" which represent the network. */
	__u8 len;
};

/*
 * Returns true if @type (which is assumed to have been extracted from a ICMP
 * header) represents a packet which is an error response.
 */
bool is_icmp6_error(__u8 type);
bool is_icmp4_error(__u8 type);

/*
 * A copy of the entire running configuration, excluding databases.
 */
struct jool_globals {
	struct ipv6_prefix pool6;

	struct in6_addr pool6791v6;
	struct in_addr pool6791v4;

	/*
	 * "true" if the Traffic Class field of translated IPv6 headers should
	 * always be zeroized.
	 * Otherwise it will be copied from the IPv4 header's TOS field.
	 */
	bool reset_traffic_class;
	/*
	 * "true" if the Type of Service (TOS) field of translated IPv4 headers
	 * should always be set as "new_tos".
	 * Otherwise it will be copied from the IPv6 header's Traffic Class
	 * field.
	 */
	bool reset_tos;
	/*
	 * If "reset_tos" is "true", this is the value the translator will
	 * always write in the TOS field of translated IPv4 headers.
	 * If "reset_tos" is "false", then this doesn't do anything.
	 */
	__u8 new_tos;

	/*
	 * Smallest reachable IPv6 MTU.
	 *
	 * Because DF does not exist in IPv6, Jool must ensure that that any
	 * DF-disabled IPv4 packet translates into fragments sized this or less.
	 * Otherwise these packets might be black-holed.
	 */
	__u32 lowest_ipv6_mtu;

	/*
	 * If the translator detects the source of the incoming packet does not
	 * implement RFC 1191, these are the plateau values used to determine a
	 * likely path MTU for outgoing ICMPv6 fragmentation needed packets.
	 * The translator is supposed to pick the greatest plateau value that is
	 * less than the incoming packet's Total Length field.
	 */
	struct mtu_plateaus plateaus;

	/*
	 * Amend the UDP checksum of incoming IPv4-UDP packets
	 * when it's zero? Otherwise these packets will be
	 * dropped (because they're illegal in IPv6).
	 */
	bool compute_udp_csum_zero;
};

#endif /* SRC_MOD_COMMON_TYPES_H_ */
