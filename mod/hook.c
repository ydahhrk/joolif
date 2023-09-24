/*
 * Adapted from snull, from the book "Linux Device Drivers" by Alessandro Rubini
 * and Jonathan Corbet, published by O'Reilly & Associates.
 */

#include <linux/module.h>
#include <linux/ioctl.h>

#include "xlat/core.h"
#include "xlat/log.h"
#include "xlat/translation_state.h"

MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_LICENSE("GPL v2");

#define JCMD_POOL6		(SIOCDEVPRIVATE + 1)
#define JCMD_POOL6791V4		(SIOCDEVPRIVATE + 2)
#define JCMD_POOL6791V6		(SIOCDEVPRIVATE + 3)
#define JCMD_LI6M		(SIOCDEVPRIVATE + 4)
#define JCMD_AUCZ		(SIOCDEVPRIVATE + 5)

struct net_device *joolif_dev;

static struct jool_globals cfg = {
	/* 64:ff9b::/96 */
	.pool6.addr.s6_addr32[0] = htonl(0x0064ff9b),
	.pool6.len = 96,

	/* 2001:db8:100::/40 */
//	.pool6.addr.s6_addr32[0] = htonl(0x20010db8),
//	.pool6.addr.s6_addr32[1] = htonl(0x01000000),
//	.pool6.len = 40,

	.reset_traffic_class = false,
	.reset_tos = false,
	.new_tos = 0,
	.lowest_ipv6_mtu = 1280,
	.plateaus.values = {
		65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68
	},
	.plateaus.count = 11,
	.compute_udp_csum_zero = false,
};

static struct rtnl_link_stats64 stats;

int joolif_open(struct net_device *dev)
{
	memcpy(dev->dev_addr, "646464", ETH_ALEN);
	netif_start_queue(dev);
	return 0;
}

int joolif_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static void send_packet(struct sk_buff *skb, struct net_device *dev)
{
	struct sk_buff *next;

	for (; skb != NULL; skb = next) {
		next = skb->next;
		skb->next = NULL;
		skb->dev = dev;
		netif_rx(skb);
	}
}

int joolif_start_xmit(struct sk_buff *in, struct net_device *dev)
{
	struct xlation state;

	pr_info("Received a packet.\n");

	skb_pull(in, ETH_HLEN); /* TODO check len >= ETH_HLEN first */

	memset(&state, 0, sizeof(state));
	state.ns = dev_net(dev);
	state.dev = dev;
	state.cfg = &cfg;
	state.stats = &stats;

	jool_xlat(&state, in);
	dev_kfree_skb(in);

	if (state.out.skb)
		send_packet(state.out.skb, dev);

	return 0;
}

static __u32 addr6_get_bit(const struct in6_addr *addr, unsigned int pos)
{
	__u32 quadrant; /* As in, @addr has 4 "quadrants" of 32 bits each. */
	__u32 mask;

	/* "pos >> 5" is a more efficient version of "pos / 32". */
	quadrant = be32_to_cpu(addr->s6_addr32[pos >> 5]);
	/* "pos & 0x1FU" is a more efficient version of "pos % 32". */
	mask = 1U << (31 - (pos & 0x1FU));

	return quadrant & mask;
}

static int prefix6_validate(const struct ipv6_prefix *prefix)
{
	unsigned int i;

	if (prefix->len > 128) {
		pr_err("Prefix length %u is too high.\n", prefix->len);
		return EINVAL;
	}

	for (i = prefix->len; i < 128; i++) {
		if (addr6_get_bit(&prefix->addr, i)) {
			pr_err("'%pI6c/%u' seems to have a suffix; please fix.\n",
					&prefix->addr, prefix->len);
			return EINVAL;
		}
	}

	return 0;
}

static int joolif_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	union {
		struct ipv6_prefix p6;
		struct in6_addr a6;
		struct in_addr a4;
		uint32_t u32;
		uint8_t u8;
	} buf;
	int error;

	switch (cmd) {
	case JCMD_POOL6:
		error = copy_from_user(&buf.p6, ifr->ifr_data, sizeof(buf.p6));
		if (error)
			goto efault;
		error = prefix6_validate(&buf.p6);
		if (error)
			return error;
		cfg.pool6 = buf.p6;
		log_debug("new pool6: %pI6c/%u", &cfg.pool6.addr, cfg.pool6.len);
		return 0;

	case JCMD_POOL6791V6:
		error = copy_from_user(&buf.a6, ifr->ifr_data, sizeof(buf.a6));
		if (error)
			goto efault;
		cfg.pool6791v6 = buf.a6;
		log_debug("new pool6791v6: %pI6c", &cfg.pool6791v6);
		return 0;

	case JCMD_POOL6791V4:
		error = copy_from_user(&buf.a4, ifr->ifr_data, sizeof(buf.a4));
		if (error)
			goto efault;
		cfg.pool6791v4 = buf.a4;
		log_debug("new pool6791v4: %pI4", &cfg.pool6791v4);
		return 0;

	case JCMD_LI6M:
		error = copy_from_user(&buf.u32, ifr->ifr_data, sizeof(buf.u32));
		if (error)
			goto efault;
		if (buf.u32 < 1280) {
			pr_err("lowest-ipv6-mtu out of range: %u < 1280\n",
			       buf.u32);
			return -ERANGE;
		}
		cfg.lowest_ipv6_mtu = buf.u32;
		log_debug("new lowest-ipv6-mtu: %u", cfg.lowest_ipv6_mtu);
		return 0;

	case JCMD_AUCZ:
		error = copy_from_user(&buf.u8, ifr->ifr_data, sizeof(buf.u8));
		if (error)
			goto efault;
		cfg.compute_udp_csum_zero = buf.u8;
		log_debug("new amend-udp-checksum-zero: %u",
			  cfg.compute_udp_csum_zero);
		return 0;
	}

	log_debug("Unrecognized ioctl.");
	return 0;

efault:
	pr_err("copy_from_user() errored: %d\n", error);
	return -EFAULT;
}

static void joolif_get_stats64(struct net_device *dev,
			       struct rtnl_link_stats64 *storage)
{
	*storage = stats;
}

static const struct net_device_ops joolif_netdev_ops = {
	.ndo_open            = joolif_open,
	.ndo_stop            = joolif_stop,
	.ndo_start_xmit      = joolif_start_xmit,
	.ndo_do_ioctl        = joolif_ioctl,
	.ndo_get_stats64     = joolif_get_stats64,
};

void joolif_init(struct net_device *dev)
{
//	netif_keep_dst(dev);

	ether_setup(dev);
	dev->watchdog_timeo = 5; /* TODO ? */
	dev->netdev_ops = &joolif_netdev_ops;
	dev->flags    |= IFF_NOARP | IFF_DEBUG;
	dev->flags    &= ~IFF_MULTICAST;
	dev->features |= NETIF_F_SG | NETIF_F_FRAGLIST |  NETIF_F_HW_CSUM;
}

static int joolif_init_module(void)
{
	int error;

	joolif_dev = alloc_netdev(0, "siit%d", NET_NAME_UNKNOWN, joolif_init);
	if (joolif_dev == 0)
		return -ENOMEM;

	error = register_netdev(joolif_dev);
	if (error) {
		printk("joolif: error %i registering device \"%s\"\n",
		       error, joolif_dev->name);
		free_netdev(joolif_dev);
	}

	return error;
}

static void joolif_cleanup(void)
{
	unregister_netdev(joolif_dev);
	free_netdev(joolif_dev);
}

module_init(joolif_init_module);
module_exit(joolif_cleanup);
