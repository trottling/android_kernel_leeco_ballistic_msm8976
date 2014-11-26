/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_bridge.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

int nft_bridge_iphdr_validate(struct sk_buff *skb)
{
	struct iphdr *iph;
	u32 len;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return 0;

	iph = ip_hdr(skb);
	if (iph->ihl < 5 || iph->version != 4)
		return 0;

	len = ntohs(iph->tot_len);
	if (skb->len < len)
		return 0;
	else if (len < (iph->ihl*4))
		return 0;

	if (!pskb_may_pull(skb, iph->ihl*4))
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(nft_bridge_iphdr_validate);

int nft_bridge_ip6hdr_validate(struct sk_buff *skb)
{
	struct ipv6hdr *hdr;
	u32 pkt_len;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return 0;

	hdr = ipv6_hdr(skb);
	if (hdr->version != 6)
		return 0;

	pkt_len = ntohs(hdr->payload_len);
	if (pkt_len + sizeof(struct ipv6hdr) > skb->len)
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(nft_bridge_ip6hdr_validate);

static struct nft_af_info nft_af_bridge __read_mostly = {
	.family		= NFPROTO_BRIDGE,
	.nhooks		= NF_BR_NUMHOOKS,
	.owner		= THIS_MODULE,
};

static int nf_tables_bridge_init_net(struct net *net)
{
	net->nft.bridge = kmalloc(sizeof(struct nft_af_info), GFP_KERNEL);
	if (net->nft.bridge == NULL)
		return -ENOMEM;

	memcpy(net->nft.bridge, &nft_af_bridge, sizeof(nft_af_bridge));

	if (nft_register_afinfo(net, net->nft.bridge) < 0)
		goto err;

	return 0;
err:
	kfree(net->nft.bridge);
	return -ENOMEM;
}

static void nf_tables_bridge_exit_net(struct net *net)
{
	nft_unregister_afinfo(net->nft.bridge);
	kfree(net->nft.bridge);
}

static struct pernet_operations nf_tables_bridge_net_ops = {
	.init	= nf_tables_bridge_init_net,
	.exit	= nf_tables_bridge_exit_net,
};

static int __init nf_tables_bridge_init(void)
{
	return register_pernet_subsys(&nf_tables_bridge_net_ops);
}

static void __exit nf_tables_bridge_exit(void)
{
	return unregister_pernet_subsys(&nf_tables_bridge_net_ops);
}

module_init(nf_tables_bridge_init);
module_exit(nf_tables_bridge_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_ALIAS_NFT_FAMILY(AF_BRIDGE);
