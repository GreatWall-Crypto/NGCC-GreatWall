#ifndef GF521_H
#define GF521_H

#include <assert.h>
#include <immintrin.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BLOCK521_BITS 521
#define BLOCK521_WORDS 9
#define BLOCK521_BYTES 66
#define BLOCK521_REDUCTION_TERM 32

typedef struct { uint64_t data[BLOCK521_WORDS]; } block521;

static inline void block521_canonicalize(block521* a)
{
    a->data[8] &= UINT64_C(0x1ff);
}
static inline bool block521_is_canonical(const block521* a)
{
    return (a->data[8] & ~UINT64_C(0x1ff)) == 0;
}
static inline void block521_load_to_block(block521* out, const uint8_t* in)
{
    assert((in[65] & 0xfe) == 0);
    block521 value = {{0}};
    memcpy(value.data, in, BLOCK521_BYTES);
    block521_canonicalize(&value);
    *out = value;
}
static inline void block521_load_words(block521* out, const uint64_t in[BLOCK521_WORDS])
{
    assert((in[8] & ~UINT64_C(0x1ff)) == 0);
    memmove(out->data, in, sizeof(out->data));
    block521_canonicalize(out);
}
static inline void block521_store_from_block(uint8_t* out, const block521* in)
{
    assert(block521_is_canonical(in));
    memmove(out, in->data, BLOCK521_BYTES);
}
static inline block521 block521_xor(block521 x, block521 y)
{
    block521 out;
    for (size_t i = 0; i < BLOCK521_WORDS; ++i)
        out.data[i] = x.data[i] ^ y.data[i];
    block521_canonicalize(&out);
    return out;
}
static inline bool block521_is_zero(const block521* value)
{
    uint64_t combined = 0;
    for (size_t i = 0; i < BLOCK521_WORDS; ++i) combined |= value->data[i];
    return combined == 0;
}
static inline bool block521_dot_is_one(const block521* a, const block521* b)
{
    uint64_t combined = 0;
    for (size_t i = 0; i < BLOCK521_WORDS; ++i)
        combined ^= a->data[i] & b->data[i];
    return __builtin_parityll(combined) != 0;
}
static inline void block521_mask(block521* x) { block521_canonicalize(x); }
static inline block521 block521_set_one(void)
{
    block521 out = {{1, 0, 0, 0, 0, 0, 0, 0, 0}};
    return out;
}

static inline void gf521_clmul128(__m128i out[2], __m128i a, __m128i b)
{
    const __m128i lo = _mm_clmulepi64_si128(a, b, 0x00);
    const __m128i hi = _mm_clmulepi64_si128(a, b, 0x11);
    const __m128i ax = _mm_xor_si128(a, _mm_srli_si128(a, 8));
    const __m128i bx = _mm_xor_si128(b, _mm_srli_si128(b, 8));
    const __m128i middle = _mm_xor_si128(
        _mm_clmulepi64_si128(ax, bx, 0x00), _mm_xor_si128(lo, hi));
    out[0] = _mm_xor_si128(lo, _mm_slli_si128(middle, 8));
    out[1] = _mm_xor_si128(hi, _mm_srli_si128(middle, 8));
}
static inline void gf521_clmul256(__m128i out[4], const __m128i a[2],
                                  const __m128i b[2])
{
    __m128i lo[2], hi[2], middle[2];
    gf521_clmul128(lo, a[0], b[0]);
    gf521_clmul128(hi, a[1], b[1]);
    gf521_clmul128(middle, _mm_xor_si128(a[0], a[1]), _mm_xor_si128(b[0], b[1]));
    middle[0] = _mm_xor_si128(middle[0], _mm_xor_si128(lo[0], hi[0]));
    middle[1] = _mm_xor_si128(middle[1], _mm_xor_si128(lo[1], hi[1]));
    out[0] = lo[0];
    out[1] = _mm_xor_si128(lo[1], middle[0]);
    out[2] = _mm_xor_si128(hi[0], middle[1]);
    out[3] = hi[1];
}
static inline void gf521_clmul512(__m128i out[8], const __m128i a[4],
                                  const __m128i b[4])
{
    __m128i lo[4], hi[4], middle[4];
    const __m128i ax[2] = {_mm_xor_si128(a[0], a[2]), _mm_xor_si128(a[1], a[3])};
    const __m128i bx[2] = {_mm_xor_si128(b[0], b[2]), _mm_xor_si128(b[1], b[3])};
    gf521_clmul256(lo, a, b);
    gf521_clmul256(hi, a + 2, b + 2);
    gf521_clmul256(middle, ax, bx);
    for (size_t i = 0; i < 4; ++i)
        middle[i] = _mm_xor_si128(middle[i], _mm_xor_si128(lo[i], hi[i]));
    out[0] = lo[0]; out[1] = lo[1];
    out[2] = _mm_xor_si128(lo[2], middle[0]);
    out[3] = _mm_xor_si128(lo[3], middle[1]);
    out[4] = _mm_xor_si128(hi[0], middle[2]);
    out[5] = _mm_xor_si128(hi[1], middle[3]);
    out[6] = hi[2]; out[7] = hi[3];
}

static inline void clmul521_product(__m128i out[9], const __m128i a[5],
                                    const __m128i b[5])
{
    const __m128i at = _mm_and_si128(a[4], _mm_set_epi64x(0, 0x1ff));
    const __m128i bt = _mm_and_si128(b[4], _mm_set_epi64x(0, 0x1ff));
    gf521_clmul512(out, a, b);
    out[8] = _mm_clmulepi64_si128(at, bt, 0x00);
    for (size_t i = 0; i < 4; ++i) {
        const __m128i low = _mm_xor_si128(_mm_clmulepi64_si128(a[i], bt, 0x00),
                                         _mm_clmulepi64_si128(b[i], at, 0x00));
        const __m128i high = _mm_xor_si128(_mm_clmulepi64_si128(a[i], bt, 0x01),
                                          _mm_clmulepi64_si128(b[i], at, 0x01));
        out[i + 4] = _mm_xor_si128(out[i + 4],
            _mm_xor_si128(low, _mm_slli_si128(high, 8)));
        out[i + 5] = _mm_xor_si128(out[i + 5], _mm_srli_si128(high, 8));
    }
}

static inline void sqr521(__m128i out[9], const __m128i in[5])
{
    const __m128i a0 = in[0], a1 = in[1], a2 = in[2], a3 = in[3];
    const __m128i a4 = _mm_and_si128(in[4], _mm_set_epi64x(0, 0x1ff));
    out[0] = _mm_clmulepi64_si128(a0, a0, 0x00);
    out[1] = _mm_clmulepi64_si128(a0, a0, 0x11);
    out[2] = _mm_clmulepi64_si128(a1, a1, 0x00);
    out[3] = _mm_clmulepi64_si128(a1, a1, 0x11);
    out[4] = _mm_clmulepi64_si128(a2, a2, 0x00);
    out[5] = _mm_clmulepi64_si128(a2, a2, 0x11);
    out[6] = _mm_clmulepi64_si128(a3, a3, 0x00);
    out[7] = _mm_clmulepi64_si128(a3, a3, 0x11);
    out[8] = _mm_clmulepi64_si128(a4, a4, 0x00);
}

static inline void block521_fold_words(block521* out, const uint64_t w[17])
{
    const uint64_t h0 = (w[8] >> 9) | (w[9] << 55);
    const uint64_t h1 = (w[9] >> 9) | (w[10] << 55);
    const uint64_t h2 = (w[10] >> 9) | (w[11] << 55);
    const uint64_t h3 = (w[11] >> 9) | (w[12] << 55);
    const uint64_t h4 = (w[12] >> 9) | (w[13] << 55);
    const uint64_t h5 = (w[13] >> 9) | (w[14] << 55);
    const uint64_t h6 = (w[14] >> 9) | (w[15] << 55);
    const uint64_t h7 = (w[15] >> 9) | (w[16] << 55);
    const uint64_t h8 = w[16] >> 9;
    const uint64_t t8 = (w[8] & UINT64_C(0x1ff)) ^ h8 ^ (h8 << 32) ^ (h7 >> 32);
    const uint64_t overflow = t8 >> 9;
    out->data[0] = w[0] ^ h0 ^ (h0 << 32) ^ overflow ^ (overflow << 32);
    out->data[1] = w[1] ^ h1 ^ (h1 << 32) ^ (h0 >> 32);
    out->data[2] = w[2] ^ h2 ^ (h2 << 32) ^ (h1 >> 32);
    out->data[3] = w[3] ^ h3 ^ (h3 << 32) ^ (h2 >> 32);
    out->data[4] = w[4] ^ h4 ^ (h4 << 32) ^ (h3 >> 32);
    out->data[5] = w[5] ^ h5 ^ (h5 << 32) ^ (h4 >> 32);
    out->data[6] = w[6] ^ h6 ^ (h6 << 32) ^ (h5 >> 32);
    out->data[7] = w[7] ^ h7 ^ (h7 << 32) ^ (h6 >> 32);
    out->data[8] = t8 & UINT64_C(0x1ff);
}

static inline void reduce_clmul521(__m128i out[5], const __m128i in[9])
{
    uint64_t words[18];
    memcpy(words, in, sizeof(words));
    for (int bit = 1151; bit >= 521; --bit) {
        const uint64_t selected = UINT64_C(0) - ((words[bit >> 6] >> (bit & 63)) & 1);
        words[bit >> 6] ^= (UINT64_C(1) << (bit & 63)) & selected;
        const int low = bit - 521;
        const int mid = low + 32;
        words[low >> 6] ^= (UINT64_C(1) << (low & 63)) & selected;
        words[mid >> 6] ^= (UINT64_C(1) << (mid & 63)) & selected;
    }
    for (size_t i = 0; i < 4; ++i)
        out[i] = _mm_set_epi64x(words[2*i + 1], words[2*i]);
    out[4] = _mm_set_epi64x(0, words[8] & UINT64_C(0x1ff));
}
#ifndef GREATWALL_GF521_FAST_REDUCTION
#define GREATWALL_GF521_FAST_REDUCTION 1
#endif
static inline void reduce_clmul521_fold_product(__m128i out[5], const __m128i in[9])
{
    uint64_t words[18];
    memcpy(words, in, sizeof(words));
    assert((words[16] >> 17) == 0 && words[17] == 0);
    block521 result;
    block521_fold_words(&result, words);
    for (size_t i = 0; i < 4; ++i)
        out[i] = _mm_set_epi64x(result.data[2*i + 1], result.data[2*i]);
    out[4] = _mm_set_epi64x(0, result.data[8]);
}
static inline void reduce_clmul521_product(__m128i out[5], const __m128i in[9])
{
#if GREATWALL_GF521_FAST_REDUCTION
    reduce_clmul521_fold_product(out, in);
#else
    reduce_clmul521(out, in);
#endif
}
static inline void gf521_load_vectors(__m128i out[5], const block521* in)
{
    for (size_t i = 0; i < 4; ++i)
        out[i] = _mm_loadu_si128((const __m128i*)&in->data[2*i]);
    out[4] = _mm_set_epi64x(0, in->data[8] & UINT64_C(0x1ff));
}
static inline void gf521_store_vectors(block521* out, const __m128i in[5])
{
    for (size_t i = 0; i < 4; ++i)
        _mm_storeu_si128((__m128i*)&out->data[2*i], in[i]);
    out->data[8] = (uint64_t)_mm_cvtsi128_si64(in[4]) & UINT64_C(0x1ff);
}
static inline void block521_sqr(block521* out, const block521* in)
{
    __m128i input[5], product[9], result[5];
    gf521_load_vectors(input, in);
    sqr521(product, input);
    reduce_clmul521_product(result, product);
    gf521_store_vectors(out, result);
}
static inline void block521_mul(block521* out, const block521* a, const block521* b)
{
    __m128i av[5], bv[5], product[9], result[5];
    gf521_load_vectors(av, a);
    gf521_load_vectors(bv, b);
    clmul521_product(product, av, bv);
    reduce_clmul521_product(result, product);
    gf521_store_vectors(out, result);
}

static inline void block521_pow_words(block521* block, const uint64_t exponent[9])
{
    const block521 base = *block;
    block521 result = block521_set_one();
    for (int bit = 520; bit >= 0; --bit) {
        block521_sqr(&result, &result);
        if ((exponent[bit >> 6] >> (bit & 63)) & 1)
            block521_mul(&result, &result, &base);
    }
    *block = result;
}
static inline void block521_mersenne_inverse1_binary(block521* block)
{
    static const uint64_t exponent[9] = {
        UINT64_C(0xaaa9555554aaaaa9), UINT64_C(0x4aaaaaa5555552aa),
        UINT64_C(0x55552aaaaa955555), UINT64_C(0xa9555554aaaaaa55),
        UINT64_C(0xaaaaa9555554aaaa), UINT64_C(0x554aaaaaa5555552),
        UINT64_C(0x5555552aaaaa9555), UINT64_C(0xaaa9555554aaaaaa),
        UINT64_C(0xaa)};
    block521_pow_words(block, exponent);
}
static inline void block521_mersenne_inverse2_binary(block521* block)
{
    static const uint64_t exponent[9] = {
        UINT64_C(0x5556aaaaab555555), UINT64_C(0xb555555aaaaaad55),
        UINT64_C(0xaaaad555556aaaaa), UINT64_C(0x56aaaaab555555aa),
        UINT64_C(0x555556aaaaab5555), UINT64_C(0xaab555555aaaaaad),
        UINT64_C(0xaaaaaad555556aaa), UINT64_C(0x5556aaaaab555555),
        UINT64_C(0x155)};
    block521_pow_words(block, exponent);
}
static inline void block521_square_n(block521* out, const block521* in, unsigned count)
{
    *out = *in;
    for (unsigned i = 0; i < count; ++i) block521_sqr(out, out);
}

static inline void block521_mersenne_inverse1_chain(block521* block)
{
    const block521 x = *block;
    block521 s2, s3, s5, s10, s11, pm1, p, r2, r4, r8, r9, t;
    block521_square_n(&s2, &x, 2);
    block521_mul(&s2, &s2, &x);
    block521_square_n(&s3, &s2, 2);
    block521_mul(&s3, &s3, &x);
    block521_square_n(&s5, &s3, 4);
    block521_mul(&s5, &s5, &s2);
    block521_square_n(&s10, &s5, 10);
    block521_mul(&s10, &s10, &s5);
    block521_square_n(&s11, &s10, 2);
    block521_mul(&s11, &s11, &x);
    block521_square_n(&pm1, &s11, 3);
    block521_mul(&p, &pm1, &x);
    block521_square_n(&r2, &p, 25);
    block521_mul(&r2, &r2, &p);
    block521_square_n(&r4, &r2, 50);
    block521_mul(&r4, &r4, &r2);
    block521_square_n(&r8, &r4, 100);
    block521_mul(&r8, &r8, &r4);
    block521_square_n(&r9, &r8, 25);
    block521_mul(&r9, &r9, &p);
    block521_square_n(&r9, &r9, 25);
    block521_mul(&r9, &r9, &pm1);
    block521_square_n(&t, &r9, 248);
    block521_mul(&t, &t, &r9);
    block521_square_n(&t, &t, 23);
    block521_mul(block, &t, &p);
}

static inline void block521_mersenne_inverse2_chain(block521* block)
{
    const block521 x = *block;
    block521 s2, s3, s6, s12, pm1, p, d, r2, r4, r8, r9, t;
    block521_square_n(&s2, &x, 2);
    block521_mul(&s2, &s2, &x);
    block521_square_n(&s3, &s2, 2);
    block521_mul(&s3, &s3, &x);
    block521_square_n(&s6, &s3, 6);
    block521_mul(&s6, &s6, &s3);
    block521_square_n(&s12, &s6, 12);
    block521_mul(&s12, &s12, &s6);
    block521_sqr(&pm1, &s12);
    block521_mul(&p, &pm1, &x);
    block521_mul(&d, &p, &pm1);
    block521_square_n(&r2, &p, 25);
    block521_mul(&r2, &r2, &p);
    block521_square_n(&r4, &r2, 50);
    block521_mul(&r4, &r4, &r2);
    block521_square_n(&r8, &r4, 100);
    block521_mul(&r8, &r8, &r4);
    block521_square_n(&r9, &r8, 25);
    block521_mul(&r9, &r9, &p);
    block521_square_n(&r9, &r9, 25);
    block521_mul(&r9, &r9, &pm1);
    block521_square_n(&t, &r9, 248);
    block521_mul(&t, &t, &r9);
    block521_square_n(&t, &t, 24);
    block521_mul(block, &t, &d);
}
#ifndef GREATWALL_GF521_INVERSE_CHAIN
#define GREATWALL_GF521_INVERSE_CHAIN 1
#endif
static inline void block521_mersenne_inverse1(block521* block)
{
#if GREATWALL_GF521_INVERSE_CHAIN
    block521_mersenne_inverse1_chain(block);
#else
    block521_mersenne_inverse1_binary(block);
#endif
}
static inline void block521_mersenne_inverse2(block521* block)
{
#if GREATWALL_GF521_INVERSE_CHAIN
    block521_mersenne_inverse2_chain(block);
#else
    block521_mersenne_inverse2_binary(block);
#endif
}
static inline void block521_multiply_with_GF2_matrix(
    block521* block, const uint64_t matrix[521][BLOCK521_WORDS])
{
    block521 out = {{0}};
    for (size_t row = 0; row < BLOCK521_BITS; ++row) {
        uint64_t combined = 0;
        for (size_t word = 0; word < BLOCK521_WORDS; ++word)
            combined ^= block->data[word] & matrix[row][word];
        out.data[row >> 6] |= (uint64_t)__builtin_parityll(combined) << (row & 63);
    }
    *block = out;
}
#endif
