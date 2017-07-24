/* Minimal Linux-like bit manipulation helper functions
 * (reduced version for alfred)
 *
 * Copyright (c) 2012-2014, Sven Eckelmann <sven@narfation.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __LINUX_LIKE_BITOPS_H__
#define __LINUX_LIKE_BITOPS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__GNUC__)
#define  BITOPS_BUILTIN_USE 1
#endif

#if defined(_MSC_VER)
#define __inline__ __inline
#endif

/**
 * BITOPS_BUILD_BUG_ON - create "negative array" build error on expression
 * @e: expression which is considered to be a "bug"
 */
#define BITOPS_BUILD_BUG_ON(e) ((void)sizeof(char[1 - 2 * !!(e)]))

/**
 * BITOPS_DIV_CEIL - calculate quotient of integer division (round up)
 * @numerator: side effect free expression for numerator of division
 * @denominator: side effect free expression for denominator of division
 *
 * numerator and denominator must be from a type which can store
 * denominator + numerator without overflow. denominator must be larger than 0
 * and numerator must be positive.
 *
 * WARNING @numerator expression must be side-effect free
 */
#define BITOPS_DIV_CEIL(numerator, denominator) \
	(((numerator) + (denominator) - 1) / (denominator))

/**
 * BITS_PER_BYTE - number of bits per byte/char
 */
#define BITS_PER_BYTE	8

/**
 * BITS_PER_LONG - number of bits per long
 */
#define BITS_PER_LONG (sizeof(unsigned long) * BITS_PER_BYTE)

/**
 * BITS_TO_LONGS - return number of longs to save at least bit 0..(bits - 1)
 * @bits: number of required bits
 */
#define BITS_TO_LONGS(bits) \
	BITOPS_DIV_CEIL(bits, BITS_PER_LONG)

/**
 * DECLARE_BITMAP - declare bitmap to store at least bit 0..(bits -1)
 * @bitmap: name for the new bitmap
 * @bits: number of required bits
 */
#define DECLARE_BITMAP(bitmap, bits) \
	unsigned long bitmap[BITS_TO_LONGS(bits)]

/**
 * BITMAP_FIRST_WORD_MASK - return unsigned long mask for least significant long
 * @start: offset to first bits
 *
 * All bits which can be modified in the least significant unsigned long for
 * offset @start in the bitmap will be set to 1. All other bits will be set to
 * zero
 */
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) % BITS_PER_LONG))

/**
 * BITMAP_LAST_WORD_MASK - return unsigned long mask for most significant long
 * @bits: number of bits in complete bitmap
 *
 * All bits which can be modified in the most significant unsigned long in the
 * bitmap will be set to 1. All other bits will be set to zero
 */
#define BITMAP_LAST_WORD_MASK(bits) (~0UL >> (-(bits) % BITS_PER_LONG))

/**
 * bitops_ffs() - find (least significant) first set bit plus one
 * @x: unsigned long to check
 *
 * Return: plus-one index of first set bit; zero when x is zero
 */
static __inline__ size_t bitops_ffs(unsigned long x)
{
#ifdef BITOPS_BUILTIN_USE
	return __builtin_ffsl(x);
#else
	size_t i = 1;

	BITOPS_BUILD_BUG_ON(BITS_PER_LONG != 32 && BITS_PER_LONG != 64);

	if (x == 0)
		return 0;

	if (BITS_PER_LONG == 64) {
		if ((0x00000000fffffffful & x) == 0) {
			i += 32;
			x >>= 32;
		}
	}

	if ((0x0000fffful & x) == 0) {
		i += 16;
		x >>= 16;
	}

	if ((0x00fful & x) == 0) {
		i += 8;
		x >>= 8;
	}

	if ((0x0ful & x) == 0) {
		i += 4;
		x >>= 4;
	}

	if ((0x3ul & x) == 0) {
		i += 2;
		x >>= 2;
	}

	if ((0x1ul & x) == 0) {
		i += 1;
		x >>= 1;
	}

	return i;
#endif
}

/**
 * hweight32() - number of set bits in an uint32_t
 * @x: uint32_t to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight32(uint32_t x)
{
	static const uint32_t m1 = UINT32_C(0x55555555);
	static const uint32_t m2 = UINT32_C(0x33333333);
	static const uint32_t m4 = UINT32_C(0x0f0f0f0f);

	/* x = (x & m1) + ((x >>  1) & m1); */
	x -= (x >> 1) & m1;
	x = (x & m2) + ((x >>  2) & m2);
	x = (x + (x >> 4)) & m4;
	x += x >> 8;
	x += x >> 16;

	return x & 0x3f;
}

/**
 * hweight64() - number of set bits in an uint64_t
 * @x: uint64_t to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight64(uint64_t x)
{
	if (BITS_PER_LONG >= 64) {
		static const uint64_t m1 = UINT64_C(0x5555555555555555);
		static const uint64_t m2 = UINT64_C(0x3333333333333333);
		static const uint64_t m4 = UINT64_C(0x0f0f0f0f0f0f0f0f);

		/* x = (x & m1) + ((x >>  1) & m1); */
		x -= (x >> 1) & m1;
		x = (x & m2) + ((x >>  2) & m2);
		x = (x + (x >> 4)) & m4;
		x += x >> 8;
		x += x >> 16;
		x += x >> 32;

		return x & 0x7f;
	} else {
		return hweight32((uint32_t)x) + hweight32((uint32_t)(x >> 32));
	}
}

/**
 * hweight_long() - number of set bits in an unsigned long
 * @x: unsigned long to sum up
 *
 * Return: number of set bits
 */
static __inline__ unsigned int hweight_long(unsigned long x)
{
#ifdef BITOPS_BUILTIN_USE
	return __builtin_popcountl(x);
#else
	size_t i;

	if (BITS_PER_LONG == 64)
		return hweight64((uint64_t)x);

	if (BITS_PER_LONG == 32)
		return hweight32((uint32_t)x);

	for (i = 0; x; i++)
		x &= x - 1;

	return i;
#endif
}

/**
 * bitmap_zero() - Initializes bitmap with zero
 * @bitmap: bitmap to modify
 * @bits: number of bits
 *
 * Initializes all bits to zero. This also includes the overhead bits in the
 * last unsigned long which will not be used.
 */
static __inline__ void bitmap_zero(unsigned long *bitmap, size_t bits)
{
	memset(bitmap, 0, BITS_TO_LONGS(bits) * sizeof(unsigned long));
}

/**
 * set_bit() - Set bit in bitmap to one
 * @bit: address of bit to modify
 * @bitmap: bitmap to modify
 */
static __inline__ void set_bit(size_t bit, unsigned long *bitmap)
{
	size_t l = bit / BITS_PER_LONG;
	size_t b = bit % BITS_PER_LONG;

	bitmap[l] |= 1UL << b;
}

/**
 * find_next_bit() - Find next set bit in bitmap
 * @bitmap: bitmap to check
 * @bits: number of bits in @bitmap
 * @start: start of bits to check
 *
 * Checks the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be checked
 *
 * Return: bit position of next set bit, @bits when no set bit was found
 */
static __inline__ size_t find_next_bit(unsigned long *bitmap, size_t bits,
				       size_t start)
{
	size_t i;
	size_t pos;
	unsigned long t;
	size_t l = BITS_TO_LONGS(bits);
	size_t first_long = start / BITS_PER_LONG;
	size_t long_lower = start - (start % BITS_PER_LONG);

	if (start >= bits)
		return bits;

	t = bitmap[first_long] & BITMAP_FIRST_WORD_MASK(start);
	for (i = first_long + 1; !t && i < l; i++) {
		/* search until valid t is found */
		long_lower += BITS_PER_LONG;
		t = bitmap[i];
	}

	if (!t)
		return bits;

	pos = long_lower + bitops_ffs(t) - 1;
	if (pos >= bits)
		return bits;

	return pos;
}

/**
 * find_first_bit - Find first set bit in bitmap
 * @bitmap: bitmap to check
 * @bits: number of bits in @bitmap
 *
 * Checks the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not be checked
 *
 * Return: bit position of fist set bit, @bits when no set bit was found
 */
#define find_first_bit(bitmap, bits) find_next_bit(bitmap, bits, 0)

/**
 * for_each_set_bit - iterate over set bits in bitmap
 * @bit: current bit
 * @bitmap: bitmap to iterate over
 * @bits: number of bits in @bitmap
 *
 * WARNING expressions @bitmap and @bits must be side-effect free
 */
#define for_each_set_bit(bit, bitmap, bits) \
	for (bit = find_first_bit(bitmap, bits); \
	     bit < (bits); \
	     bit = find_next_bit(bitmap, bits, bit + 1))

/**
 * bitmap_weight() - Calculate number of set bits in bitmap
 * @bitmap: bitmap to sum up
 * @bits: number of bits
 *
 * Sums the modifiable bits in the bitmap. The overhead bits in the last
 * unsigned long will not summed up
 *
 * Return: number of set bits
 */
static __inline__ size_t bitmap_weight(const unsigned long *bitmap, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;
	size_t sum = 0;

	for (i = 0; i < l - 1; i++)
		sum += hweight_long(bitmap[i]);

	return sum + hweight_long(bitmap[l - 1] & BITMAP_LAST_WORD_MASK(bits));
}

/**
 * bitmap_empty() - Check if no bit is set in bitmap
 * @bitmap: bitmap to test
 * @bits: number of bits
 *
 * Check the modifiable bits in the bitmap for zero. The overhead bits in the
 * last unsigned long will not be checked
 *
 * Return: true when usable bits were all zero and false otherwise
 */
static __inline__ bool bitmap_empty(const unsigned long *bitmap, size_t bits)
{
	size_t l = BITS_TO_LONGS(bits);
	size_t i;

	for (i = 0; i < l - 1; i++) {
		if (bitmap[i])
			return false;
	}

	return !(bitmap[l - 1] & BITMAP_LAST_WORD_MASK(bits));
}

#ifdef __cplusplus
}
#endif

#endif /* __LINUX_LIKE_BITOPS_H__ */
