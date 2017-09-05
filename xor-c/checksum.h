#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
/**
 * ported from dpdk
 * @author: faicker.mo@gmail.com
 */

#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

#ifdef __cplusplus
extern "C" {
#endif

/** Create IPv4 address */
#define IPv4(a,b,c,d) ((uint32_t)(((a) & 0xff) << 24) | \
					   (((b) & 0xff) << 16) | \
					   (((c) & 0xff) << 8)  | \
					   ((d) & 0xff))

/** Maximal IPv4 packet length (including a header) */
#define IPV4_MAX_PKT_LEN        65535

/** Internet header length mask for version_ihl field */
#define IPV4_HDR_IHL_MASK	(0x0f)
/**
 * Internet header length field multiplier (IHL field specifies overall header
 * length in number of 4-byte words)
 */
#define IPV4_IHL_MULTIPLIER	(4)

/* Fragment Offset * Flags. */
#define	IPV4_HDR_DF_SHIFT	14
#define	IPV4_HDR_MF_SHIFT	13
#define	IPV4_HDR_FO_SHIFT	3

#define	IPV4_HDR_DF_FLAG	(1 << IPV4_HDR_DF_SHIFT)
#define	IPV4_HDR_MF_FLAG	(1 << IPV4_HDR_MF_SHIFT)

#define	IPV4_HDR_OFFSET_MASK	((1 << IPV4_HDR_MF_SHIFT) - 1)

#define	IPV4_HDR_OFFSET_UNITS	8

/*
 * IPv4 address types
 */
#define IPV4_ANY              ((uint32_t)0x00000000) /**< 0.0.0.0 */
#define IPV4_LOOPBACK         ((uint32_t)0x7f000001) /**< 127.0.0.1 */
#define IPV4_BROADCAST        ((uint32_t)0xe0000000) /**< 224.0.0.0 */
#define IPV4_ALLHOSTS_GROUP   ((uint32_t)0xe0000001) /**< 224.0.0.1 */
#define IPV4_ALLRTRS_GROUP    ((uint32_t)0xe0000002) /**< 224.0.0.2 */
#define IPV4_MAX_LOCAL_GROUP  ((uint32_t)0xe00000ff) /**< 224.0.0.255 */

/*
 * IPv4 Multicast-related macros
 */
#define IPV4_MIN_MCAST  IPv4(224, 0, 0, 0)          /**< Minimal IPv4-multicast address */
#define IPV4_MAX_MCAST  IPv4(239, 255, 255, 255)    /**< Maximum IPv4 multicast address */

#define IS_IPV4_MCAST(x) \
	((x) >= IPV4_MIN_MCAST && (x) <= IPV4_MAX_MCAST) /**< check if IPv4 address is multicast */

/**
 * @internal Calculate a sum of all words in the buffer.
 * Helper routine for the raw_cksum().
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @param sum
 *   Initial value of the sum.
 * @return
 *   sum += Sum of all words in the buffer.
 */
static inline uint32_t
__raw_cksum(const void *buf, size_t len, uint32_t sum)
{
	/* workaround gcc strict-aliasing warning */
	uintptr_t ptr = (uintptr_t)buf;
	typedef uint16_t __attribute__((__may_alias__)) u16_p;
	const u16_p *u16 = (const u16_p *)ptr;

	while (len >= (sizeof(*u16) * 4)) {
		sum += u16[0];
		sum += u16[1];
		sum += u16[2];
		sum += u16[3];
		len -= sizeof(*u16) * 4;
		u16 += 4;
	}
	while (len >= sizeof(*u16)) {
		sum += *u16;
		len -= sizeof(*u16);
		u16 += 1;
	}

	/* if length is in odd bytes */
	if (len == 1)
		sum += *((const uint8_t *)u16);

	return sum;
}

/**
 * @internal Reduce a sum to the non-complemented checksum.
 * Helper routine for the raw_cksum().
 *
 * @param sum
 *   Value of the sum.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
__raw_cksum_reduce(uint32_t sum)
{
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	return (uint16_t)sum;
}

/**
 * Process the non-complemented checksum of a buffer.
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
raw_cksum(const void *buf, size_t len)
{
	uint32_t sum;

	sum = __raw_cksum(buf, len, 0);
	return __raw_cksum_reduce(sum);
}

/**
 * Process the IPv4 checksum of an IPv4 header.
 *
 * The checksum field must be set to 0 by the caller.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline uint16_t
ipv4_cksum(const struct iphdr *ipv4_hdr)
{
	uint16_t cksum;
	cksum = raw_cksum(ipv4_hdr, sizeof(struct iphdr));
	return (cksum == 0xffff) ? cksum : ~cksum;
}

/**
 * Process the pseudo-header checksum of an IPv4 header.
 *
 * The checksum field must be set to 0 by the caller.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @return
 *   The non-complemented checksum to set in the L4 header.
 */
static inline uint16_t
ipv4_phdr_cksum(const struct iphdr *ipv4_hdr)
{
	struct ipv4_psd_header {
		uint32_t src_addr; /* IP address of source host. */
		uint32_t dst_addr; /* IP address of destination host. */
		uint8_t  zero;     /* zero. */
		uint8_t  proto;    /* L4 protocol type. */
		uint16_t len;      /* L4 length. */
	} psd_hdr;

	psd_hdr.src_addr = ipv4_hdr->saddr;
	psd_hdr.dst_addr = ipv4_hdr->daddr;
	psd_hdr.zero = 0;
	psd_hdr.proto = ipv4_hdr->protocol;
    psd_hdr.len = htons(
            (uint16_t)(ntohs(ipv4_hdr->tot_len)
                - ipv4_hdr->ihl * IPV4_IHL_MULTIPLIER));
	return raw_cksum(&psd_hdr, sizeof(psd_hdr));
}

/**
 * Process the IPv4 UDP or TCP checksum.
 *
 * The IPv4 header should not contains options. The IP and layer 4
 * checksum must be set to 0 in the packet by the caller.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline uint16_t
ipv4_udptcp_cksum(const struct iphdr *ipv4_hdr, const void *l4_hdr)
{
	uint32_t cksum;
	uint32_t l4_len;

	l4_len = ntohs(ipv4_hdr->tot_len) -
		ipv4_hdr->ihl * IPV4_IHL_MULTIPLIER;

	cksum = raw_cksum(l4_hdr, l4_len);
	cksum += ipv4_phdr_cksum(ipv4_hdr);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

/**
 * Process the pseudo-header checksum of an IPv6 header.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @return
 *   The non-complemented checksum to set in the L4 header.
 */
static inline uint16_t
ipv6_phdr_cksum(const struct ip6_hdr *ipv6_hdr)
{
	uint32_t sum;
	struct {
		uint32_t len;   /* L4 length. */
		uint32_t proto; /* L4 protocol - top 3 bytes must be zero */
	} psd_hdr;

	psd_hdr.proto = (ipv6_hdr->ip6_nxt << 24);
    psd_hdr.len = ipv6_hdr->ip6_plen;

	sum = __raw_cksum(&ipv6_hdr->ip6_src,
		sizeof(ipv6_hdr->ip6_src) + sizeof(ipv6_hdr->ip6_dst),
		0);
	sum = __raw_cksum(&psd_hdr, sizeof(psd_hdr), sum);
	return __raw_cksum_reduce(sum);
}

/**
 * Process the IPv6 UDP or TCP checksum.
 *
 * The IPv4 header should not contains options. The layer 4 checksum
 * must be set to 0 in the packet by the caller.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline uint16_t
ipv6_udptcp_cksum(const struct ip6_hdr *ipv6_hdr, const void *l4_hdr)
{
	uint32_t cksum;
	uint32_t l4_len;

	l4_len = ntohs(ipv6_hdr->ip6_plen);

	cksum = raw_cksum(l4_hdr, l4_len);
	cksum += ipv6_phdr_cksum(ipv6_hdr);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

#ifdef __cplusplus
}
#endif

#endif /* _CHECKSUM_H_ */
