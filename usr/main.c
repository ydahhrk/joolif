#include <errno.h> /* errno */
#include <net/if.h> /* IFNAMSIZ */
#include <stdint.h> /* uint32_t */
#include <stdio.h> /* fprintf */
#include <stdlib.h> /* strtoul */
#include <string.h> /* strlen, strcpy, memset, strerror */
#include <sys/socket.h> /* socket */
#include <sys/ioctl.h> /* ioctl */
#include <unistd.h> /* close */
#include <netinet/in.h> /* in6_addr, in_addr */
#include <arpa/inet.h> /* inet_pton */

#define pr_err(format, ...) fprintf(stderr, format "\n", ##__VA_ARGS__)

#define JCMD_POOL6		(SIOCDEVPRIVATE + 1)
#define JCMD_POOL6791V4		(SIOCDEVPRIVATE + 2)
#define JCMD_POOL6791V6		(SIOCDEVPRIVATE + 3)
#define JCMD_LI6M		(SIOCDEVPRIVATE + 4)
#define JCMD_AUCZ		(SIOCDEVPRIVATE + 5)

struct ipv6_prefix {
	struct in6_addr addr;
	uint8_t len;
};

struct ioctl_arg {
	int cmd;
	struct ifreq ifr;
};

static int read_ulong(char const *str, unsigned long *result, unsigned long max)
{
	unsigned long ulong;
	int error;

	errno = 0;
	ulong = strtoul(str, NULL, 10);
	if (errno) {
		error = errno;
		pr_err("Cannot parse '%s': %s", str, strerror(error));
		return error;
	}

	if (ulong > max) {
		pr_err("Cannot parse '%s': Integer too big", str);
		return ERANGE;
	}

	*result = ulong;
	return 0;
}

static int read_u8(char const *str, uint8_t *u8, uint8_t max)
{
	unsigned long ulong;
	int error;

	error = read_ulong(str, &ulong, max);
	if (!error)
		*u8 = ulong;

	return error;
}

static int read_u32(char const *str, uint32_t *u32, uint32_t max)
{
	unsigned long ulong;
	int error;

	error = read_ulong(str, &ulong, max);
	if (!error)
		*u32 = ulong;

	return error;
}

static int read_addr6(char const *str, struct in6_addr *addr)
{
	if (inet_pton(AF_INET6, str, addr) == 1)
		return 0;

	pr_err("Cannot parse '%s' as an IPv6 address.", str);
	return EINVAL;
}

static int read_addr4(char const *str, struct in_addr *addr)
{
	if (inet_pton(AF_INET, str, addr) == 1)
		return 0;

	pr_err("Cannot parse '%s' as an IPv4 address.", str);
	return EINVAL;
}

/* [addr + null chara] + / + pref len */
#define STR_MAX_LEN (INET6_ADDRSTRLEN + 1 + 3)
static int read_prefix6(const char *str, struct ipv6_prefix *prefix)
{
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		pr_err("String too long: %s", str);
		return EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "/");
	if (!token) {
		pr_err("Cannot parse '%s' as an IPv6 address.", str);
		return EINVAL;
	}

	error = read_addr6(token, &prefix->addr);
	if (error)
		return error;

	token = strtok(NULL, "/");
	if (!token) {
		prefix->len = 128;
		return 0;
	}

	return read_u8(token, &prefix->len, 128);
}

static int read_arg(struct ioctl_arg *arg, char const *key, char const *value)
{
	static union {
		struct ipv6_prefix p6;
		struct in6_addr a6;
		struct in_addr a4;
		uint32_t u32;
		uint8_t u8;
	} buffer;
	int error;

	if (strcmp(key, "pool6") == 0) {
		arg->cmd = JCMD_POOL6;
		error = read_prefix6(value, &buffer.p6);

	} else if (strcmp(key, "pool6791v6") == 0) {
		arg->cmd = JCMD_POOL6791V6;
		error = read_addr6(value, &buffer.a6);

	} else if (strcmp(key, "pool6791v4") == 0) {
		arg->cmd = JCMD_POOL6791V4;
		error = read_addr4(value, &buffer.a4);

	} else if (strcmp(key, "lowest-ipv6-mtu") == 0) {
		arg->cmd = JCMD_LI6M;
		error = read_u32(value, &buffer.u32, UINT32_MAX);

	} else if (strcmp(key, "amend-udp-checksum-zero") == 0) {
		arg->cmd = JCMD_AUCZ;
		error = read_u8(value, &buffer.u8, 1);

	} else {
		pr_err("Unrecognized argument name: %s", key);
		pr_err("Available values: pool6 pool6791v6 pool6791v4 "
				"lowest-ipv6-mtu amend-udp-checksum-zero");
		return EINVAL;
	}

	if (!error)
		arg->ifr.ifr_data = (void *) &buffer;
	return error;
}

int main(int argc, char **argv) {

	int sockfd = 0;
	struct ioctl_arg arg;
	int error;

	if (argc != 4) {
		pr_err("Usage: joolif <interface> <key> <value>");
		return EINVAL;
	}

	if (strlen(argv[0]) > IFNAMSIZ - 1) {
		pr_err("Interface name too long: %zu > %d",
		       strlen(argv[0]), IFNAMSIZ - 1);
		return EINVAL;
	}

	memset(&arg, 0, sizeof(arg));
	strcpy(arg.ifr.ifr_name, argv[1]);
	error = read_arg(&arg, argv[2], argv[3]);
	if (error)
		return error;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		error = errno;
		pr_err("Cannot open socket: %s", strerror(error));
		return error;
	}

	if (ioctl(sockfd, arg.cmd, &arg.ifr) < 0) {
		error = errno;
		pr_err("ioctl error: %s", strerror(error));
	}

	close(sockfd);
	return error;

}
