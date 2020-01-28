/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Assignment 5: Implement and use this */
#include <linux/ip.h>
#include <linux/icmp.h>


/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};


/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto; /* NOTICE: unsigned type */
};

#define VLAN_MAX_DEPTH 4

/* Assignment 4: Implement and use this */
static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}


/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;


	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh += 1;
	}

	nh->pos = vlh;

	return h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{

	struct ipv6hdr *ip6h = nh->pos;
	

	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{

	struct icmp6hdr * icmp6 = nh->pos;

	if ( icmp6 + 1 > data_end)
		return -1;

	nh->pos = icmp6 + 1;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_type;
}


/* Assignment 5: Implement and use this */
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iph){

	struct iphdr * ip = nh->pos;
	int hdrsize = ip->ihl * 4; /*	IHL == the number of 32-bit words in the header */

	if( ip + 1 > data_end) {
		return -1;
	 } else {
		if ( nh->pos + hdrsize > data_end)
			return -1;
	}

	*iph = ip;
	nh->pos += hdrsize;

	return ip->protocol;
}
									

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					void *data_end,
					struct icmphdr **icmph){

	struct icmphdr * icmp = nh->pos;
	
	if ( icmp + 1 > data_end)
		return -1;

	*icmph = icmp;
	nh->pos = icmp + 1;

	return icmp->type;
}


SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ipv6hdr;
	struct icmp6hdr *icmp6;
	struct iphdr *iph;
	struct icmphdr *icmph;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type = 0;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */

	/*	Layer 2 parsing	      */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != bpf_htons(ETH_P_IPV6) && nh_type != bpf_htons(ETH_P_IP)){
		action = XDP_DROP;
		goto out;
	}

	/*	Layer 3 parsing	      */
	if ( nh_type == bpf_htons(ETH_P_IPV6)){
		nh_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	
		/*	Layer 4 parsing       */
		if ( nh_type == IPPROTO_ICMPV6 ){
			
			nh_type = parse_icmp6hdr(&nh, data_end, &icmp6);
			
               		if (nh_type != ICMPV6_ECHO_REQUEST)
                       		goto out;

               		if (bpf_ntohs(icmp6->icmp6_sequence) % 2 == 0)
                       		action = XDP_DROP;
		}

	} else if (nh_type == bpf_htons(ETH_P_IP)){

		nh_type = parse_iphdr(&nh, data_end, &iph);
		
		if( nh_type == IPPROTO_ICMP){
			
			nh_type = parse_icmphdr(&nh, data_end, &icmph);
			
			if (nh_type != ICMP_ECHO)
				goto out;
			
			if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
                                action = XDP_DROP;
		}	
	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
