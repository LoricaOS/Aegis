/* kernel/net/net.h — shared network stack types
 *
 * Included by eth.h, ip.h, udp.h, tcp.h. Contains only types, macros,
 * and the two checksum function prototypes — no protocol state.
 */
#ifndef NET_H
#define NET_H

#include <stdint.h>

/* Network-byte-order address types. Stored in wire (big-endian) order. */
typedef uint32_t ip4_addr_t;          /* network byte order */
typedef struct { uint8_t b[6]; } mac_addr_t;

/* Byte-order conversion via GCC builtins — no libc needed. */
#define htons(x)  __builtin_bswap16((uint16_t)(x))
#define ntohs(x)  __builtin_bswap16((uint16_t)(x))
#define htonl(x)  __builtin_bswap32((uint32_t)(x))
#define ntohl(x)  __builtin_bswap32((uint32_t)(x))

/* net_checksum: accumulate a running 32-bit one's-complement sum over len bytes.
 * Returns a uint32_t partial sum (NOT folded, NOT inverted).
 * Intended to be called multiple times for non-contiguous regions:
 *   uint32_t sum = 0;
 *   sum += net_checksum(pseudo_hdr, sizeof(pseudo_hdr));
 *   sum += net_checksum(payload, payload_len);
 *   header->checksum = net_checksum_finish(sum);
 */
uint32_t net_checksum(const void *data, uint32_t len);

/* net_checksum_finish: fold carry bits into 16 bits, invert (one's complement).
 * Returns the final 16-bit checksum value, ready to store in the header field.
 * A result of 0x0000 becomes 0xFFFF per RFC 768 (UDP); TCP treats 0x0000 as zero.
 */
uint16_t net_checksum_finish(uint32_t sum);

#endif /* NET_H */
