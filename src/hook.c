/*
 * Adapted from snull, from the book "Linux Device Drivers" by Alessandro Rubini
 * and Jonathan Corbet, published by O'Reilly & Associates.
 */

#include <linux/module.h>

#include "xlat/core.h"
#include "xlat/translation_state.h"

MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_LICENSE("GPL v2");

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
	state.cfg = &cfg;
	state.stats = &stats;

	jool_xlat(&state, in);
	dev_kfree_skb(in);

	if (state.out.skb)
		send_packet(state.out.skb, dev);

	return 0;
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
	.ndo_get_stats64     = joolif_get_stats64,
};

void joolif_init(struct net_device *dev)
{
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
