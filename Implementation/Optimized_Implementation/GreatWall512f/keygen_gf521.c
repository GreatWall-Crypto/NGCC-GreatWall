#include "keygen_gf521.h"
#include "gf521.h"
#include "greatwall.h"
#include "owf_alpha.h"
#include "timing.h"

GW_STATIC_ASSERT(SECURITY_PARAM == 512, "keygen_gf521 is only for GreatWall512");
GW_STATIC_ASSERT(OWF_BLOCK_SIZE == BLOCK521_BYTES, "GF521 encoding mismatch");

#define GREATWALL_KEYGEN_GF521_LOCAL_ARITH 1

static inline void keygen_gf521_square(block521* out, const block521* in)
{
#if GREATWALL_KEYGEN_GF521_LOCAL_ARITH
    assert(block521_is_canonical(in));

    const uint64_t x0 = in->data[0];
    const uint64_t x1 = in->data[1];
    const uint64_t x2 = in->data[2];
    const uint64_t x3 = in->data[3];
    const uint64_t x4 = in->data[4];
    const uint64_t x5 = in->data[5];
    const uint64_t x6 = in->data[6];
    const uint64_t x7 = in->data[7];
    const uint64_t x8 = in->data[8];
    const __m128i table = _mm_set_epi64x(0x5554515045444140, 0x1514111005040100);
    const __m128i mask = _mm_set1_epi8(15);
    const __m128i a0 = _mm_set_epi64x((long long)x1, (long long)x0);
    const __m128i lo0 = _mm_shuffle_epi8(table, _mm_and_si128(a0, mask));
    const __m128i hi0 = _mm_shuffle_epi8(table, _mm_and_si128(_mm_srli_epi64(a0, 4), mask));
    const __m128i p0 = _mm_unpacklo_epi8(lo0, hi0);
    const __m128i p1 = _mm_unpackhi_epi8(lo0, hi0);
    const __m128i a1 = _mm_set_epi64x((long long)x3, (long long)x2);
    const __m128i lo1 = _mm_shuffle_epi8(table, _mm_and_si128(a1, mask));
    const __m128i hi1 = _mm_shuffle_epi8(table, _mm_and_si128(_mm_srli_epi64(a1, 4), mask));
    const __m128i p2 = _mm_unpacklo_epi8(lo1, hi1);
    const __m128i p3 = _mm_unpackhi_epi8(lo1, hi1);
    const __m128i a2 = _mm_set_epi64x((long long)x5, (long long)x4);
    const __m128i lo2 = _mm_shuffle_epi8(table, _mm_and_si128(a2, mask));
    const __m128i hi2 = _mm_shuffle_epi8(table, _mm_and_si128(_mm_srli_epi64(a2, 4), mask));
    const __m128i p4 = _mm_unpacklo_epi8(lo2, hi2);
    const __m128i p5 = _mm_unpackhi_epi8(lo2, hi2);
    const __m128i a3 = _mm_set_epi64x((long long)x7, (long long)x6);
    const __m128i lo3 = _mm_shuffle_epi8(table, _mm_and_si128(a3, mask));
    const __m128i hi3 = _mm_shuffle_epi8(table, _mm_and_si128(_mm_srli_epi64(a3, 4), mask));
    const __m128i p6 = _mm_unpacklo_epi8(lo3, hi3);
    const __m128i p7 = _mm_unpackhi_epi8(lo3, hi3);
    const __m128i a4 = _mm_set_epi64x(0, (long long)x8);
    const __m128i lo4 = _mm_shuffle_epi8(table, _mm_and_si128(a4, mask));
    const __m128i hi4 = _mm_shuffle_epi8(table, _mm_and_si128(_mm_srli_epi64(a4, 4), mask));
    const __m128i p8 = _mm_unpacklo_epi8(lo4, hi4);
    const uint64_t w0 = (uint64_t)_mm_cvtsi128_si64(p0);
    const uint64_t w1 = (uint64_t)_mm_extract_epi64(p0, 1);
    const uint64_t w2 = (uint64_t)_mm_cvtsi128_si64(p1);
    const uint64_t w3 = (uint64_t)_mm_extract_epi64(p1, 1);
    const uint64_t w4 = (uint64_t)_mm_cvtsi128_si64(p2);
    const uint64_t w5 = (uint64_t)_mm_extract_epi64(p2, 1);
    const uint64_t w6 = (uint64_t)_mm_cvtsi128_si64(p3);
    const uint64_t w7 = (uint64_t)_mm_extract_epi64(p3, 1);
    const uint64_t w8 = (uint64_t)_mm_cvtsi128_si64(p4);
    const uint64_t w9 = (uint64_t)_mm_extract_epi64(p4, 1);
    const uint64_t w10 = (uint64_t)_mm_cvtsi128_si64(p5);
    const uint64_t w11 = (uint64_t)_mm_extract_epi64(p5, 1);
    const uint64_t w12 = (uint64_t)_mm_cvtsi128_si64(p6);
    const uint64_t w13 = (uint64_t)_mm_extract_epi64(p6, 1);
    const uint64_t w14 = (uint64_t)_mm_cvtsi128_si64(p7);
    const uint64_t w15 = (uint64_t)_mm_extract_epi64(p7, 1);
    const uint64_t w16 = (uint64_t)_mm_cvtsi128_si64(p8);

    const uint64_t h0 = (w8 >> 9) | (w9 << 55);
    const uint64_t h1 = (w9 >> 9) | (w10 << 55);
    const uint64_t h2 = (w10 >> 9) | (w11 << 55);
    const uint64_t h3 = (w11 >> 9) | (w12 << 55);
    const uint64_t h4 = (w12 >> 9) | (w13 << 55);
    const uint64_t h5 = (w13 >> 9) | (w14 << 55);
    const uint64_t h6 = (w14 >> 9) | (w15 << 55);
    const uint64_t h7 = (w15 >> 9) | (w16 << 55);
    const uint64_t h8 = w16 >> 9;
    const uint64_t t0 = w0 ^ h0 ^ (h0 << 32);
    const uint64_t t1 = w1 ^ h1 ^ (h1 << 32) ^ (h0 >> 32);
    const uint64_t t2 = w2 ^ h2 ^ (h2 << 32) ^ (h1 >> 32);
    const uint64_t t3 = w3 ^ h3 ^ (h3 << 32) ^ (h2 >> 32);
    const uint64_t t4 = w4 ^ h4 ^ (h4 << 32) ^ (h3 >> 32);
    const uint64_t t5 = w5 ^ h5 ^ (h5 << 32) ^ (h4 >> 32);
    const uint64_t t6 = w6 ^ h6 ^ (h6 << 32) ^ (h5 >> 32);
    const uint64_t t7 = w7 ^ h7 ^ (h7 << 32) ^ (h6 >> 32);
    const uint64_t t8 = (w8 & UINT64_C(0x1ff)) ^ h8 ^ (h8 << 32) ^ (h7 >> 32);
    const uint64_t overflow = t8 >> 9;
    out->data[0] = t0 ^ overflow ^ (overflow << 32);
    out->data[1] = t1;
    out->data[2] = t2;
    out->data[3] = t3;
    out->data[4] = t4;
    out->data[5] = t5;
    out->data[6] = t6;
    out->data[7] = t7;
    out->data[8] = t8 & UINT64_C(0x1ff);
#else
    block521_sqr(out, in);
#endif
}

static inline void keygen_gf521_multiply(block521* out, const block521* a, const block521* b)
{
#if GREATWALL_KEYGEN_GF521_LOCAL_ARITH
    assert(block521_is_canonical(a) && block521_is_canonical(b));

    const __m128i a0 = _mm_set_epi64x((long long)a->data[1], (long long)a->data[0]);
    const __m128i a1 = _mm_set_epi64x((long long)a->data[3], (long long)a->data[2]);
    const __m128i a2 = _mm_set_epi64x((long long)a->data[5], (long long)a->data[4]);
    const __m128i a3 = _mm_set_epi64x((long long)a->data[7], (long long)a->data[6]);
    const __m128i at = _mm_cvtsi64_si128((long long)a->data[8]);
    const __m128i b0 = _mm_set_epi64x((long long)b->data[1], (long long)b->data[0]);
    const __m128i b1 = _mm_set_epi64x((long long)b->data[3], (long long)b->data[2]);
    const __m128i b2 = _mm_set_epi64x((long long)b->data[5], (long long)b->data[4]);
    const __m128i b3 = _mm_set_epi64x((long long)b->data[7], (long long)b->data[6]);
    const __m128i bt = _mm_cvtsi64_si128((long long)b->data[8]);
    const __m128i k_ax0 = _mm_xor_si128(a0, a2);
    const __m128i k_bx0 = _mm_xor_si128(b0, b2);
    const __m128i k_ax1 = _mm_xor_si128(a1, a3);
    const __m128i k_bx1 = _mm_xor_si128(b1, b3);
    const __m128i kl_ax0 = _mm_xor_si128(a0, a1);
    const __m128i kl_bx0 = _mm_xor_si128(b0, b1);
    const __m128i kll_lo = _mm_clmulepi64_si128(a0, b0, 0x00);
    const __m128i kll_hi = _mm_clmulepi64_si128(a0, b0, 0x11);
    const __m128i kll_ax = _mm_xor_si128(a0, _mm_srli_si128(a0, 8));
    const __m128i kll_bx = _mm_xor_si128(b0, _mm_srli_si128(b0, 8));
    const __m128i kll_mid = _mm_xor_si128(_mm_clmulepi64_si128(kll_ax, kll_bx, 0x00), _mm_xor_si128(kll_lo, kll_hi));
    const __m128i kll_0 = _mm_xor_si128(kll_lo, _mm_slli_si128(kll_mid, 8));
    const __m128i kll_1 = _mm_xor_si128(kll_hi, _mm_srli_si128(kll_mid, 8));
    const __m128i klh_lo = _mm_clmulepi64_si128(a1, b1, 0x00);
    const __m128i klh_hi = _mm_clmulepi64_si128(a1, b1, 0x11);
    const __m128i klh_ax = _mm_xor_si128(a1, _mm_srli_si128(a1, 8));
    const __m128i klh_bx = _mm_xor_si128(b1, _mm_srli_si128(b1, 8));
    const __m128i klh_mid = _mm_xor_si128(_mm_clmulepi64_si128(klh_ax, klh_bx, 0x00), _mm_xor_si128(klh_lo, klh_hi));
    const __m128i klh_0 = _mm_xor_si128(klh_lo, _mm_slli_si128(klh_mid, 8));
    const __m128i klh_1 = _mm_xor_si128(klh_hi, _mm_srli_si128(klh_mid, 8));
    const __m128i klm_lo = _mm_clmulepi64_si128(kl_ax0, kl_bx0, 0x00);
    const __m128i klm_hi = _mm_clmulepi64_si128(kl_ax0, kl_bx0, 0x11);
    const __m128i klm_ax = _mm_xor_si128(kl_ax0, _mm_srli_si128(kl_ax0, 8));
    const __m128i klm_bx = _mm_xor_si128(kl_bx0, _mm_srli_si128(kl_bx0, 8));
    const __m128i klm_mid = _mm_xor_si128(_mm_clmulepi64_si128(klm_ax, klm_bx, 0x00), _mm_xor_si128(klm_lo, klm_hi));
    const __m128i klm_0 = _mm_xor_si128(klm_lo, _mm_slli_si128(klm_mid, 8));
    const __m128i klm_1 = _mm_xor_si128(klm_hi, _mm_srli_si128(klm_mid, 8));
    const __m128i kl_mid0 = _mm_xor_si128(klm_0, _mm_xor_si128(kll_0, klh_0));
    const __m128i kl_mid1 = _mm_xor_si128(klm_1, _mm_xor_si128(kll_1, klh_1));
    const __m128i kl_0 = kll_0;
    const __m128i kl_1 = _mm_xor_si128(kll_1, kl_mid0);
    const __m128i kl_2 = _mm_xor_si128(klh_0, kl_mid1);
    const __m128i kl_3 = klh_1;
    const __m128i kh_ax0 = _mm_xor_si128(a2, a3);
    const __m128i kh_bx0 = _mm_xor_si128(b2, b3);
    const __m128i khl_lo = _mm_clmulepi64_si128(a2, b2, 0x00);
    const __m128i khl_hi = _mm_clmulepi64_si128(a2, b2, 0x11);
    const __m128i khl_ax = _mm_xor_si128(a2, _mm_srli_si128(a2, 8));
    const __m128i khl_bx = _mm_xor_si128(b2, _mm_srli_si128(b2, 8));
    const __m128i khl_mid = _mm_xor_si128(_mm_clmulepi64_si128(khl_ax, khl_bx, 0x00), _mm_xor_si128(khl_lo, khl_hi));
    const __m128i khl_0 = _mm_xor_si128(khl_lo, _mm_slli_si128(khl_mid, 8));
    const __m128i khl_1 = _mm_xor_si128(khl_hi, _mm_srli_si128(khl_mid, 8));
    const __m128i khh_lo = _mm_clmulepi64_si128(a3, b3, 0x00);
    const __m128i khh_hi = _mm_clmulepi64_si128(a3, b3, 0x11);
    const __m128i khh_ax = _mm_xor_si128(a3, _mm_srli_si128(a3, 8));
    const __m128i khh_bx = _mm_xor_si128(b3, _mm_srli_si128(b3, 8));
    const __m128i khh_mid = _mm_xor_si128(_mm_clmulepi64_si128(khh_ax, khh_bx, 0x00), _mm_xor_si128(khh_lo, khh_hi));
    const __m128i khh_0 = _mm_xor_si128(khh_lo, _mm_slli_si128(khh_mid, 8));
    const __m128i khh_1 = _mm_xor_si128(khh_hi, _mm_srli_si128(khh_mid, 8));
    const __m128i khm_lo = _mm_clmulepi64_si128(kh_ax0, kh_bx0, 0x00);
    const __m128i khm_hi = _mm_clmulepi64_si128(kh_ax0, kh_bx0, 0x11);
    const __m128i khm_ax = _mm_xor_si128(kh_ax0, _mm_srli_si128(kh_ax0, 8));
    const __m128i khm_bx = _mm_xor_si128(kh_bx0, _mm_srli_si128(kh_bx0, 8));
    const __m128i khm_mid = _mm_xor_si128(_mm_clmulepi64_si128(khm_ax, khm_bx, 0x00), _mm_xor_si128(khm_lo, khm_hi));
    const __m128i khm_0 = _mm_xor_si128(khm_lo, _mm_slli_si128(khm_mid, 8));
    const __m128i khm_1 = _mm_xor_si128(khm_hi, _mm_srli_si128(khm_mid, 8));
    const __m128i kh_mid0 = _mm_xor_si128(khm_0, _mm_xor_si128(khl_0, khh_0));
    const __m128i kh_mid1 = _mm_xor_si128(khm_1, _mm_xor_si128(khl_1, khh_1));
    const __m128i kh_0 = khl_0;
    const __m128i kh_1 = _mm_xor_si128(khl_1, kh_mid0);
    const __m128i kh_2 = _mm_xor_si128(khh_0, kh_mid1);
    const __m128i kh_3 = khh_1;
    const __m128i km_ax0 = _mm_xor_si128(k_ax0, k_ax1);
    const __m128i km_bx0 = _mm_xor_si128(k_bx0, k_bx1);
    const __m128i kml_lo = _mm_clmulepi64_si128(k_ax0, k_bx0, 0x00);
    const __m128i kml_hi = _mm_clmulepi64_si128(k_ax0, k_bx0, 0x11);
    const __m128i kml_ax = _mm_xor_si128(k_ax0, _mm_srli_si128(k_ax0, 8));
    const __m128i kml_bx = _mm_xor_si128(k_bx0, _mm_srli_si128(k_bx0, 8));
    const __m128i kml_mid = _mm_xor_si128(_mm_clmulepi64_si128(kml_ax, kml_bx, 0x00), _mm_xor_si128(kml_lo, kml_hi));
    const __m128i kml_0 = _mm_xor_si128(kml_lo, _mm_slli_si128(kml_mid, 8));
    const __m128i kml_1 = _mm_xor_si128(kml_hi, _mm_srli_si128(kml_mid, 8));
    const __m128i kmh_lo = _mm_clmulepi64_si128(k_ax1, k_bx1, 0x00);
    const __m128i kmh_hi = _mm_clmulepi64_si128(k_ax1, k_bx1, 0x11);
    const __m128i kmh_ax = _mm_xor_si128(k_ax1, _mm_srli_si128(k_ax1, 8));
    const __m128i kmh_bx = _mm_xor_si128(k_bx1, _mm_srli_si128(k_bx1, 8));
    const __m128i kmh_mid = _mm_xor_si128(_mm_clmulepi64_si128(kmh_ax, kmh_bx, 0x00), _mm_xor_si128(kmh_lo, kmh_hi));
    const __m128i kmh_0 = _mm_xor_si128(kmh_lo, _mm_slli_si128(kmh_mid, 8));
    const __m128i kmh_1 = _mm_xor_si128(kmh_hi, _mm_srli_si128(kmh_mid, 8));
    const __m128i kmm_lo = _mm_clmulepi64_si128(km_ax0, km_bx0, 0x00);
    const __m128i kmm_hi = _mm_clmulepi64_si128(km_ax0, km_bx0, 0x11);
    const __m128i kmm_ax = _mm_xor_si128(km_ax0, _mm_srli_si128(km_ax0, 8));
    const __m128i kmm_bx = _mm_xor_si128(km_bx0, _mm_srli_si128(km_bx0, 8));
    const __m128i kmm_mid = _mm_xor_si128(_mm_clmulepi64_si128(kmm_ax, kmm_bx, 0x00), _mm_xor_si128(kmm_lo, kmm_hi));
    const __m128i kmm_0 = _mm_xor_si128(kmm_lo, _mm_slli_si128(kmm_mid, 8));
    const __m128i kmm_1 = _mm_xor_si128(kmm_hi, _mm_srli_si128(kmm_mid, 8));
    const __m128i km_mid0 = _mm_xor_si128(kmm_0, _mm_xor_si128(kml_0, kmh_0));
    const __m128i km_mid1 = _mm_xor_si128(kmm_1, _mm_xor_si128(kml_1, kmh_1));
    const __m128i km_0 = kml_0;
    const __m128i km_1 = _mm_xor_si128(kml_1, km_mid0);
    const __m128i km_2 = _mm_xor_si128(kmh_0, km_mid1);
    const __m128i km_3 = kmh_1;
    const __m128i k_mid0 = _mm_xor_si128(km_0, _mm_xor_si128(kl_0, kh_0));
    const __m128i k_mid1 = _mm_xor_si128(km_1, _mm_xor_si128(kl_1, kh_1));
    const __m128i k_mid2 = _mm_xor_si128(km_2, _mm_xor_si128(kl_2, kh_2));
    const __m128i k_mid3 = _mm_xor_si128(km_3, _mm_xor_si128(kl_3, kh_3));
    const __m128i k_0 = kl_0;
    const __m128i k_1 = kl_1;
    const __m128i k_2 = _mm_xor_si128(kl_2, k_mid0);
    const __m128i k_3 = _mm_xor_si128(kl_3, k_mid1);
    const __m128i k_4 = _mm_xor_si128(kh_0, k_mid2);
    const __m128i k_5 = _mm_xor_si128(kh_1, k_mid3);
    const __m128i k_6 = kh_2;
    const __m128i k_7 = kh_3;
    const __m128i cross_lo0 = _mm_xor_si128(_mm_clmulepi64_si128(a0, bt, 0x00), _mm_clmulepi64_si128(b0, at, 0x00));
    const __m128i cross_hi0 = _mm_xor_si128(_mm_clmulepi64_si128(a0, bt, 0x01), _mm_clmulepi64_si128(b0, at, 0x01));
    const __m128i cross0 = _mm_xor_si128(cross_lo0, _mm_slli_si128(cross_hi0, 8));
    const __m128i carry0 = _mm_srli_si128(cross_hi0, 8);
    const __m128i cross_lo1 = _mm_xor_si128(_mm_clmulepi64_si128(a1, bt, 0x00), _mm_clmulepi64_si128(b1, at, 0x00));
    const __m128i cross_hi1 = _mm_xor_si128(_mm_clmulepi64_si128(a1, bt, 0x01), _mm_clmulepi64_si128(b1, at, 0x01));
    const __m128i cross1 = _mm_xor_si128(cross_lo1, _mm_slli_si128(cross_hi1, 8));
    const __m128i carry1 = _mm_srli_si128(cross_hi1, 8);
    const __m128i cross_lo2 = _mm_xor_si128(_mm_clmulepi64_si128(a2, bt, 0x00), _mm_clmulepi64_si128(b2, at, 0x00));
    const __m128i cross_hi2 = _mm_xor_si128(_mm_clmulepi64_si128(a2, bt, 0x01), _mm_clmulepi64_si128(b2, at, 0x01));
    const __m128i cross2 = _mm_xor_si128(cross_lo2, _mm_slli_si128(cross_hi2, 8));
    const __m128i carry2 = _mm_srli_si128(cross_hi2, 8);
    const __m128i cross_lo3 = _mm_xor_si128(_mm_clmulepi64_si128(a3, bt, 0x00), _mm_clmulepi64_si128(b3, at, 0x00));
    const __m128i cross_hi3 = _mm_xor_si128(_mm_clmulepi64_si128(a3, bt, 0x01), _mm_clmulepi64_si128(b3, at, 0x01));
    const __m128i cross3 = _mm_xor_si128(cross_lo3, _mm_slli_si128(cross_hi3, 8));
    const __m128i carry3 = _mm_srli_si128(cross_hi3, 8);
    const __m128i top = _mm_clmulepi64_si128(at, bt, 0x00);
    const __m128i p0 = k_0;
    const __m128i p1 = k_1;
    const __m128i p2 = k_2;
    const __m128i p3 = k_3;
    const __m128i p4 = _mm_xor_si128(k_4, cross0);
    const __m128i p5 = _mm_xor_si128(_mm_xor_si128(k_5, cross1), carry0);
    const __m128i p6 = _mm_xor_si128(_mm_xor_si128(k_6, cross2), carry1);
    const __m128i p7 = _mm_xor_si128(_mm_xor_si128(k_7, cross3), carry2);
    const __m128i p8 = _mm_xor_si128(top, carry3);
    const uint64_t w0 = (uint64_t)_mm_cvtsi128_si64(p0);
    const uint64_t w1 = (uint64_t)_mm_extract_epi64(p0, 1);
    const uint64_t w2 = (uint64_t)_mm_cvtsi128_si64(p1);
    const uint64_t w3 = (uint64_t)_mm_extract_epi64(p1, 1);
    const uint64_t w4 = (uint64_t)_mm_cvtsi128_si64(p2);
    const uint64_t w5 = (uint64_t)_mm_extract_epi64(p2, 1);
    const uint64_t w6 = (uint64_t)_mm_cvtsi128_si64(p3);
    const uint64_t w7 = (uint64_t)_mm_extract_epi64(p3, 1);
    const uint64_t w8 = (uint64_t)_mm_cvtsi128_si64(p4);
    const uint64_t w9 = (uint64_t)_mm_extract_epi64(p4, 1);
    const uint64_t w10 = (uint64_t)_mm_cvtsi128_si64(p5);
    const uint64_t w11 = (uint64_t)_mm_extract_epi64(p5, 1);
    const uint64_t w12 = (uint64_t)_mm_cvtsi128_si64(p6);
    const uint64_t w13 = (uint64_t)_mm_extract_epi64(p6, 1);
    const uint64_t w14 = (uint64_t)_mm_cvtsi128_si64(p7);
    const uint64_t w15 = (uint64_t)_mm_extract_epi64(p7, 1);
    const uint64_t w16 = (uint64_t)_mm_cvtsi128_si64(p8);
    const uint64_t h0 = (w8 >> 9) | (w9 << 55);
    const uint64_t h1 = (w9 >> 9) | (w10 << 55);
    const uint64_t h2 = (w10 >> 9) | (w11 << 55);
    const uint64_t h3 = (w11 >> 9) | (w12 << 55);
    const uint64_t h4 = (w12 >> 9) | (w13 << 55);
    const uint64_t h5 = (w13 >> 9) | (w14 << 55);
    const uint64_t h6 = (w14 >> 9) | (w15 << 55);
    const uint64_t h7 = (w15 >> 9) | (w16 << 55);
    const uint64_t h8 = w16 >> 9;
    const uint64_t t0 = w0 ^ h0 ^ (h0 << 32);
    const uint64_t t1 = w1 ^ h1 ^ (h1 << 32) ^ (h0 >> 32);
    const uint64_t t2 = w2 ^ h2 ^ (h2 << 32) ^ (h1 >> 32);
    const uint64_t t3 = w3 ^ h3 ^ (h3 << 32) ^ (h2 >> 32);
    const uint64_t t4 = w4 ^ h4 ^ (h4 << 32) ^ (h3 >> 32);
    const uint64_t t5 = w5 ^ h5 ^ (h5 << 32) ^ (h4 >> 32);
    const uint64_t t6 = w6 ^ h6 ^ (h6 << 32) ^ (h5 >> 32);
    const uint64_t t7 = w7 ^ h7 ^ (h7 << 32) ^ (h6 >> 32);
    const uint64_t t8 = (w8 & UINT64_C(0x1ff)) ^ h8 ^ (h8 << 32) ^ (h7 >> 32);
    const uint64_t overflow = t8 >> 9;
    out->data[0] = t0 ^ overflow ^ (overflow << 32);
    out->data[1] = t1;
    out->data[2] = t2;
    out->data[3] = t3;
    out->data[4] = t4;
    out->data[5] = t5;
    out->data[6] = t6;
    out->data[7] = t7;
    out->data[8] = t8 & UINT64_C(0x1ff);
#else
    block521_mul(out, a, b);
#endif
}

static inline void keygen_gf521_square_n(block521* out, const block521* in, unsigned count)
{
    *out = *in;
    for (unsigned i = 0; i < count; ++i)
        keygen_gf521_square(out, out);
}

static inline void keygen_gf521_inverse1(block521* block)
{
#if GREATWALL_GF521_INVERSE_CHAIN
    const block521 x = *block;
    block521 s2, s3, s5, s10, s11, pm1, p, r2, r4, r8, r9, t;
    keygen_gf521_square_n(&s2, &x, 2);
    keygen_gf521_multiply(&s2, &s2, &x);
    keygen_gf521_square_n(&s3, &s2, 2);
    keygen_gf521_multiply(&s3, &s3, &x);
    keygen_gf521_square_n(&s5, &s3, 4);
    keygen_gf521_multiply(&s5, &s5, &s2);
    keygen_gf521_square_n(&s10, &s5, 10);
    keygen_gf521_multiply(&s10, &s10, &s5);
    keygen_gf521_square_n(&s11, &s10, 2);
    keygen_gf521_multiply(&s11, &s11, &x);
    keygen_gf521_square_n(&pm1, &s11, 3);
    keygen_gf521_multiply(&p, &pm1, &x);
    keygen_gf521_square_n(&r2, &p, 25);
    keygen_gf521_multiply(&r2, &r2, &p);
    keygen_gf521_square_n(&r4, &r2, 50);
    keygen_gf521_multiply(&r4, &r4, &r2);
    keygen_gf521_square_n(&r8, &r4, 100);
    keygen_gf521_multiply(&r8, &r8, &r4);
    keygen_gf521_square_n(&r9, &r8, 25);
    keygen_gf521_multiply(&r9, &r9, &p);
    keygen_gf521_square_n(&r9, &r9, 25);
    keygen_gf521_multiply(&r9, &r9, &pm1);
    keygen_gf521_square_n(&t, &r9, 248);
    keygen_gf521_multiply(&t, &t, &r9);
    keygen_gf521_square_n(&t, &t, 23);
    keygen_gf521_multiply(block, &t, &p);
#else
    block521_mersenne_inverse1_binary(block);
#endif
}

static inline void keygen_gf521_inverse2(block521* block)
{
#if GREATWALL_GF521_INVERSE_CHAIN
    const block521 x = *block;
    block521 s2, s3, s6, s12, pm1, p, d, r2, r4, r8, r9, t;
    keygen_gf521_square_n(&s2, &x, 2);
    keygen_gf521_multiply(&s2, &s2, &x);
    keygen_gf521_square_n(&s3, &s2, 2);
    keygen_gf521_multiply(&s3, &s3, &x);
    keygen_gf521_square_n(&s6, &s3, 6);
    keygen_gf521_multiply(&s6, &s6, &s3);
    keygen_gf521_square_n(&s12, &s6, 12);
    keygen_gf521_multiply(&s12, &s12, &s6);
    keygen_gf521_square(&pm1, &s12);
    keygen_gf521_multiply(&p, &pm1, &x);
    keygen_gf521_multiply(&d, &p, &pm1);
    keygen_gf521_square_n(&r2, &p, 25);
    keygen_gf521_multiply(&r2, &r2, &p);
    keygen_gf521_square_n(&r4, &r2, 50);
    keygen_gf521_multiply(&r4, &r4, &r2);
    keygen_gf521_square_n(&r8, &r4, 100);
    keygen_gf521_multiply(&r8, &r8, &r4);
    keygen_gf521_square_n(&r9, &r8, 25);
    keygen_gf521_multiply(&r9, &r9, &p);
    keygen_gf521_square_n(&r9, &r9, 25);
    keygen_gf521_multiply(&r9, &r9, &pm1);
    keygen_gf521_square_n(&t, &r9, 248);
    keygen_gf521_multiply(&t, &t, &r9);
    keygen_gf521_square_n(&t, &t, 24);
    keygen_gf521_multiply(block, &t, &d);
#else
    block521_mersenne_inverse2_binary(block);
#endif
}
static inline void keygen_gf521_matrix(block521* x, const uint64_t matrix[521][9])
{
    block521_multiply_with_GF2_matrix(x, matrix);
}

bool greatwall_keygen_pubkey_521(uint8_t* pk, const uint8_t* sk)
{
    block521 key, iv;
    block521_load_to_block(&key, sk);
    block521_load_to_block(&iv, sk + BLOCK521_BYTES);

    FAEST_TIMING_DECLARE();
    FAEST_TIMING_START();
    owf_block alpha0, alpha1;
    if (!derive_owf_alpha(&alpha0, &iv, 0) ||
        !derive_owf_alpha(&alpha1, &iv, 1) ||
        owf_alpha_is_zero(&alpha0) || owf_alpha_is_zero(&alpha1)) {
        FAEST_TIMING_PRINT("keygen_owf/derive_alpha_and_check");
        return false;
    }
    FAEST_TIMING_PRINT("keygen_owf/derive_alpha_and_check");

    FAEST_TIMING_START();
    block521 state = key;
    block521 rc0, rc1;
    block521_load_words(&rc0, greatwall_rc_521[0]);
    block521_load_words(&rc1, greatwall_rc_521[1]);
    FAEST_TIMING_PRINT("keygen_owf/load_constants");

    FAEST_TIMING_START();
    keygen_gf521_matrix(&state, greatwall_mat_521_0);
    state = block521_xor(state, rc0);
    FAEST_TIMING_PRINT("keygen_owf/linear_matrix0_and_add_constant");
    FAEST_TIMING_START();
    keygen_gf521_inverse1(&state);
    FAEST_TIMING_PRINT("keygen_owf/mersenne_inverse1");
    FAEST_TIMING_START();
    if (!owf_alpha_dot_is_one(&alpha0, &state)) {
        FAEST_TIMING_PRINT("keygen_owf/check_alpha0");
        return false;
    }
    FAEST_TIMING_PRINT("keygen_owf/check_alpha0");

    FAEST_TIMING_START();
    state = block521_xor(state, key);
    keygen_gf521_matrix(&state, greatwall_mat_521_1);
    state = block521_xor(state, iv);
    const block521 tmp = state;
    FAEST_TIMING_PRINT("keygen_owf/linear_matrix1_and_mix_input");
    FAEST_TIMING_START();
    keygen_gf521_inverse2(&state);
    FAEST_TIMING_PRINT("keygen_owf/mersenne_inverse2");
    FAEST_TIMING_START();
    if (!owf_alpha_dot_is_one(&alpha1, &state)) {
        FAEST_TIMING_PRINT("keygen_owf/check_alpha1");
        return false;
    }
    FAEST_TIMING_PRINT("keygen_owf/check_alpha1");

    FAEST_TIMING_START();
    keygen_gf521_matrix(&state, greatwall_mat_521_2);
    state = block521_xor(state, rc1);
    state = block521_xor(state, tmp);
    state = block521_xor(state, key);

    block521_store_from_block(pk, &state);
    block521_store_from_block(pk + BLOCK521_BYTES, &iv);
    FAEST_TIMING_PRINT("keygen_owf/linear_matrix2_and_pack_output");
    return true;
}
