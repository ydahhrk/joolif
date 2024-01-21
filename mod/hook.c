/*
 * Adapted from snull (from the book "Linux Device Drivers" by Alessandro Rubini
 * and Jonathan Corbet, published by O'Reilly & Associates) and veth.
 */

/*
 * Development notes/to-dos:
 *
 * - I removed from veth everything xdp-related. Might want to restore it later.
 * - snull uses ioctls while veth uses Netlink, for seemingly the same purpose.
 *   The latter is probably the smarter way of receiving arguments from
 *   userspace, but might require tweaking the `ip link` binaries.
 * - Stats removed. I haven't figured out how to print them in userspace,
 *   so I can't test them.
 */

#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/version.h>

#include "xlat/core.h"
#include "xlat/log.h"
#include "xlat/translation_state.h"

MODULE_AUTHOR("Alberto Leiva Popper");
MODULE_LICENSE("GPL v2");

#define DRV_NAME "siit"

/* Inherited from veth, unused placeholder for now. */
struct siit_priv {
	atomic64_t		dropped;
};

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

	.pool6791v4.s_addr = htonl(INADDR_DUMMY),

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

int joolif_open(struct net_device *dev)
{
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

	skb_pull(in, ETH_HLEN); /* TODO check len >= ETH_HLEN first? */

	memset(&state, 0, sizeof(state));
	state.ns = dev_net(dev);
	state.dev = dev;
	state.cfg = &cfg;

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

static const struct net_device_ops joolif_netdev_ops = {
	.ndo_open		= joolif_open,
	.ndo_stop		= joolif_stop,
	.ndo_start_xmit		= joolif_start_xmit,
	.ndo_do_ioctl		= joolif_ioctl,
};

/*
 * Inherited from veth.
 *
 * Netfilter/iptables Jool decently translates GSO, frag_list and checksums.
 * However, I don't yet know what these flags do nor exactly what they expect us
 * to do, so I decided to leave them out for now.
 */
#define SIIT_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HW_CSUM | \
		       NETIF_F_RXCSUM | /* NETIF_F_HIGHDMA | ? */ \
		       NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL)

/*
 * Mixed from snull and veth.
 */
static void siit_setup(struct net_device *dev)
{
	ether_setup(dev);

//	dev->watchdog_timeo = 5; TODO ?
	dev->flags    |= IFF_NOARP | IFF_DEBUG;
	dev->flags    &= ~IFF_MULTICAST;
	dev->features |= NETIF_F_SG | NETIF_F_FRAGLIST |  NETIF_F_HW_CSUM;

	/* pskb_may_pull() crashes on shared packets.
	 * https://elixir.bootlin.com/linux/latest/source/net/core/skbuff.c#L2091
	 * There might be other functions that reject shareds. */
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	/* Jool doesn't care about the L2 address, so whatever I guess. */
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	/* Is this relevant? Packet order matters nothing to SIIT. */
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->netdev_ops = &joolif_netdev_ops;
//	dev->features |= SIIT_FEATURES;
	dev->needs_free_netdev = true;
//	dev->priv_destructor = ;
//	dev->pcpu_stat_type = NETDEV_PCPU_STAT_NONE; /* Newer kernels only. */
	dev->max_mtu = ETH_MAX_MTU;

//	dev->hw_features = SIIT_FEATURES;
//	dev->hw_enc_features = SIIT_FEATURES;
//	dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
//	netif_set_tso_max_size(dev, GSO_MAX_SIZE);
}

/*
 * Inherited from veth. Seems reasonable.
 */
static int is_valid_siit_mtu(int mtu)
{
	return mtu >= ETH_MIN_MTU && mtu <= ETH_MAX_MTU;
}

/*
 * Inherited from veth. Seems reasonable.
 */
static int siit_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	if (tb[IFLA_MTU]) {
		if (!is_valid_siit_mtu(nla_get_u32(tb[IFLA_MTU])))
			return -EINVAL;
	}
	return 0;
}

/*
 * Inherited from veth.c. I have no idea why it exists.
 *
 * 	ip link add type siit numtxqueues 5 numrxqueues 6
 *
 * results in
 *
 *	dev->num_tx_queues: 5
 *	dev->num_rx_queues: 6
 *	dev->real_num_tx_queues: 5
 *	dev->real_num_rx_queues: 6
 *
 * If numtxqueues/numrxqueues default, rtnl_create_link() uses
 * siit_get_num_queues() to set num_tx_queues/num_rx_queues. In my quad core,
 * this results in
 *
 *	dev->num_tx_queues: 4
 *	dev->num_rx_queues: 4
 *	dev->real_num_tx_queues: 4
 *	dev->real_num_rx_queues: 4
 *
 * Then this function downgrades the last two to 1.
 *
 * This looks like nonsense.
 */
static int siit_init_queues(struct net_device *dev, struct nlattr *tb[])
{
	int err;

	if (!tb[IFLA_NUM_TX_QUEUES] && dev->num_tx_queues > 1) {
		err = netif_set_real_num_tx_queues(dev, 1);
		if (err)
			return err;
	}
	if (!tb[IFLA_NUM_RX_QUEUES] && dev->num_rx_queues > 1) {
		err = netif_set_real_num_rx_queues(dev, 1);
		if (err)
			return err;
	}

	return 0;
}

/* https://github.com/torvalds/linux/commit/872f690341948b502c93318f806d821c5 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define NLA_STRCPY nla_strscpy
#else
#define NLA_STRCPY nla_strlcpy
#endif

/*
 * Simplified version of veth's newlink.
 */
static int siit_newlink(struct net *src_net, struct net_device *dev,
			struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	int err;

	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		NLA_STRCPY(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		return err;

	pr_info("Added device '%s'.\n", dev->name);

	err = siit_init_queues(dev, tb);
	if (err) {
		unregister_netdevice(dev);
		return err;
	}

	return 0;
}

/*
 * Inherited from veth. Not actually needed; if dellink is NULL,
 * __rtnl_link_register() automatically sets it as unregister_netdevice_queue().
 *
 * If you don't add anything, probably delete this function on pr_info() purge
 * day.
 */
static void siit_dellink(struct net_device *dev, struct list_head *head)
{
	pr_info("Removing device '%s'.\n", dev->name);
	unregister_netdevice_queue(dev, head);
}

/*
 * Inherited from veth. Seems like a reasonable implementation.
 */
static unsigned int siit_get_num_queues(void)
{
	int queues = num_possible_cpus();
	return (queues > 4096) ? 4096 : queues;
}

static struct rtnl_link_ops siit_link_ops = {
	.kind			= DRV_NAME,
	.priv_size		= sizeof(struct siit_priv),
	.setup			= siit_setup,
	.validate		= siit_validate,
	.newlink		= siit_newlink,
	.dellink		= siit_dellink,

	/* nlargs not needed for now, so .policy and .maxtype excluded */

	/*
	 * It seems veth uses .get_link_net to return the peer dev's namespace.
	 * The kernel seems to only use this incidentally (as an ugly hack),
	 * and has no meaning in SIIT anyway.
	 */

	.get_num_tx_queues	= siit_get_num_queues,
	.get_num_rx_queues	= siit_get_num_queues,
};

static int joolif_init(void)
{
	return rtnl_link_register(&siit_link_ops);
}

static void joolif_exit(void)
{
	rtnl_link_unregister(&siit_link_ops);
}

module_init(joolif_init);
module_exit(joolif_exit);
