/**
 * vim: set ts=4 :
 * =============================================================================
 * SipHash-2-4 (Aumasson & Bernstein, https://131002.net/siphash/)
 * Compact standalone implementation, public domain reference algorithm.
 * Keyed PRF: 128-bit key, arbitrary input, 64-bit output.
 * =============================================================================
 */

#ifndef _INCLUDE_A2SQCACHE_SIPHASH_H_
#define _INCLUDE_A2SQCACHE_SIPHASH_H_

#include <stddef.h>
#include <stdint.h>

#define SIPHASH_KEY_SIZE 16

static inline uint64_t SipHash_ROTL(uint64_t x, int b)
{
	return (x << b) | (x >> (64 - b));
}

static inline uint64_t SipHash_U8To64LE(const uint8_t *p)
{
	return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
		((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

#define SIPHASH_ROUND(v0, v1, v2, v3) \
	do { \
		v0 += v1; v1 = SipHash_ROTL(v1, 13); v1 ^= v0; v0 = SipHash_ROTL(v0, 32); \
		v2 += v3; v3 = SipHash_ROTL(v3, 16); v3 ^= v2; \
		v0 += v3; v3 = SipHash_ROTL(v3, 21); v3 ^= v0; \
		v2 += v1; v1 = SipHash_ROTL(v1, 17); v1 ^= v2; v2 = SipHash_ROTL(v2, 32); \
	} while (0)

static inline uint64_t SipHash24(const uint8_t key[SIPHASH_KEY_SIZE], const uint8_t *in, size_t inlen)
{
	const uint64_t k0 = SipHash_U8To64LE(key);
	const uint64_t k1 = SipHash_U8To64LE(key + 8);

	uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
	uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
	uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
	uint64_t v3 = 0x7465646279746573ULL ^ k1;

	const uint8_t *end = in + inlen - (inlen % 8);
	for (; in != end; in += 8)
	{
		uint64_t m = SipHash_U8To64LE(in);
		v3 ^= m;
		SIPHASH_ROUND(v0, v1, v2, v3);
		SIPHASH_ROUND(v0, v1, v2, v3);
		v0 ^= m;
	}

	uint64_t b = ((uint64_t)inlen) << 56;
	for (size_t i = 0; i < (inlen & 7); i++)
		b |= ((uint64_t)in[i]) << (8 * i);

	v3 ^= b;
	SIPHASH_ROUND(v0, v1, v2, v3);
	SIPHASH_ROUND(v0, v1, v2, v3);
	v0 ^= b;

	v2 ^= 0xff;
	SIPHASH_ROUND(v0, v1, v2, v3);
	SIPHASH_ROUND(v0, v1, v2, v3);
	SIPHASH_ROUND(v0, v1, v2, v3);
	SIPHASH_ROUND(v0, v1, v2, v3);

	return v0 ^ v1 ^ v2 ^ v3;
}

#undef SIPHASH_ROUND

#endif // _INCLUDE_A2SQCACHE_SIPHASH_H_
