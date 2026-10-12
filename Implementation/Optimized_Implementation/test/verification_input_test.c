#define _GNU_SOURCE
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "api.h"
#include "faest.h"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"

/* This deterministic source belongs only to the regression executable. */
DRNG_ctx drng_algorithm;
int rand_bytes(uint8_t *out, size_t len)
{
    return get_random_number(&drng_algorithm, out, len * 8);
}

static unsigned long checks;
static int track_allocations;
static size_t allocation_attempts;

void *__real_malloc(size_t size);
void *__real_aligned_alloc(size_t alignment, size_t size);
int __real_posix_memalign(void **ptr, size_t alignment, size_t size);

void *__wrap_malloc(size_t size)
{
    if (track_allocations) ++allocation_attempts;
    return __real_malloc(size);
}

void *__wrap_aligned_alloc(size_t alignment, size_t size)
{
    if (track_allocations) ++allocation_attempts;
    return __real_aligned_alloc(alignment, size);
}

int __wrap_posix_memalign(void **ptr, size_t alignment, size_t size)
{
    if (track_allocations) ++allocation_attempts;
    return __real_posix_memalign(ptr, alignment, size);
}

#define CHECK(test) do { \
    if (!(test)) { fprintf(stderr, "FAIL line=%d: %s\n", __LINE__, #test); exit(1); } \
    ++checks; \
} while (0)

enum { MAX_MESSAGE = 1024 };
static uint8_t message[MAX_MESSAGE], sk[CRYPTO_SECRETKEYBYTES];
static uint8_t original_pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t *pk, *signature, *signed_message;
static uint8_t opened[MAX_MESSAGE + 1];
static size_t message_len;

/* Place each exact-size input immediately before an inaccessible page. */
static uint8_t *guarded_buffer(size_t size)
{
    const long page_result = sysconf(_SC_PAGESIZE);
    CHECK(page_result > 0);
    const size_t page = (size_t)page_result;
    const size_t usable = (size + page - 1) / page * page;
    uint8_t *base = mmap(NULL, usable + 2 * page, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(base != MAP_FAILED);
    CHECK(mprotect(base + page, usable, PROT_READ | PROT_WRITE) == 0);
    return base + page + usable - size;
}

static int decode(const char *hex, uint8_t *out, size_t len)
{
    if (strcspn(hex, "\r\n") != 2 * len) return 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned value;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1) return 0;
        out[i] = (uint8_t)value;
    }
    return 1;
}

/* Load a known valid SM3 signature without changing the shared KAT file. */
static void load_first_vector(const char *path)
{
    FILE *input = fopen(path, "rb");
    CHECK(input != NULL);
    char *line = NULL;
    size_t capacity = 0;
    int have_pk = 0, have_sk = 0, have_message = 0, have_signature = 0;
    while (getline(&line, &capacity, input) >= 0) {
        if (!strncmp(line, "PK = ", 5))
            have_pk = decode(line + 5, pk, CRYPTO_PUBLICKEYBYTES);
        else if (!strncmp(line, "SK = ", 5))
            have_sk = decode(line + 5, sk, CRYPTO_SECRETKEYBYTES);
        else if (!strncmp(line, "M_Len = ", 8)) {
            message_len = strtoul(line + 8, NULL, 10);
            CHECK(message_len > 0 && message_len <= MAX_MESSAGE);
        } else if (!strncmp(line, "M = ", 4))
            have_message = decode(line + 4, message, message_len);
        else if (!strncmp(line, "Sn = ", 5)) {
            have_signature = decode(line + 5, signature, CRYPTO_BYTES);
            break;
        }
    }
    free(line);
    fclose(input);
    CHECK(have_pk && have_sk && have_message && have_signature);
}

static void restore_signed_message(void)
{
    memcpy(signed_message, message, message_len);
    memcpy(signed_message + message_len, signature, CRYPTO_BYTES);
}

/* Every rejected signed message must leave output bytes untouched. */
static void reject_open(const uint8_t *sm, unsigned long long size, const uint8_t *key)
{
    unsigned long long outlen = ULLONG_MAX;
    memset(opened, 0xa5, sizeof(opened));
    CHECK(crypto_sign_open(opened, &outlen, sm, size, key) == -1);
    CHECK(outlen == 0);
    for (size_t i = 0; i < sizeof(opened); ++i) CHECK(opened[i] == 0xa5);
}

static void check_public_key(int valid)
{
    unsigned long long outlen = ULLONG_MAX;
    const int detached = sig_verify(pk, CRYPTO_PUBLICKEYBYTES,
        signature, CRYPTO_BYTES, message, message_len);
    CHECK(detached == (valid ? 0 : -1));
    CHECK(faest_verify(signature, message, message_len, pk) == (valid != 0));
    if (valid) {
        CHECK(crypto_sign_open(opened, &outlen, signed_message,
              message_len + CRYPTO_BYTES, pk) == 0);
        CHECK(outlen == message_len && !memcmp(opened, message, message_len));
    } else reject_open(signed_message, message_len + CRYPTO_BYTES, pk);
}

static void check_lengths_and_nulls(void)
{
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *inaccessible = mmap(NULL, page, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    for (unsigned long long len = 0; len < CRYPTO_BYTES; ++len) {
        CHECK(sig_verify(pk, CRYPTO_PUBLICKEYBYTES, inaccessible, len,
                         message, message_len) == -1);
        unsigned long long outlen = ULLONG_MAX;
        CHECK(crypto_sign_open(opened, &outlen, inaccessible, len, pk) == -1);
        CHECK(outlen == 0);
    }
    const unsigned long long bad_lengths[] = {
        CRYPTO_BYTES + 1ULL, CRYPTO_BYTES + 64ULL, ULLONG_MAX
    };
    for (size_t i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); ++i)
        CHECK(sig_verify(pk, CRYPTO_PUBLICKEYBYTES, inaccessible, bad_lengths[i],
                         message, message_len) == -1);
    for (unsigned long long len = 0; len < CRYPTO_PUBLICKEYBYTES; ++len)
        CHECK(sig_verify(inaccessible, len, signature, CRYPTO_BYTES,
                         message, message_len) == -2);
    CHECK(sig_verify(inaccessible, CRYPTO_PUBLICKEYBYTES + 1ULL,
                     signature, CRYPTO_BYTES, message, message_len) == -2);
    CHECK(sig_verify(inaccessible, ULLONG_MAX,
                     signature, CRYPTO_BYTES, message, message_len) == -2);
    CHECK(sig_verify(NULL, CRYPTO_PUBLICKEYBYTES, signature, CRYPTO_BYTES,
                     message, message_len) == -2);
    CHECK(sig_verify(pk, CRYPTO_PUBLICKEYBYTES, NULL, CRYPTO_BYTES,
                     message, message_len) == -1);
    CHECK(sig_verify(pk, CRYPTO_PUBLICKEYBYTES, signature, CRYPTO_BYTES,
                     NULL, 1) == -1);
    CHECK(sig_verify(pk, CRYPTO_PUBLICKEYBYTES, signature, CRYPTO_BYTES,
                     inaccessible, ULLONG_MAX) == -1);
    CHECK(sig_verify(pk, CRYPTO_PUBLICKEYBYTES, signature, CRYPTO_BYTES,
                     inaccessible, PTRDIFF_MAX) == -1);
    reject_open(inaccessible, ULLONG_MAX, pk);
    reject_open(NULL, message_len + CRYPTO_BYTES, pk);
    reject_open(signed_message, message_len + CRYPTO_BYTES, NULL);
    unsigned long long outlen = ULLONG_MAX;
    CHECK(crypto_sign_open(NULL, &outlen, signed_message,
                           message_len + CRYPTO_BYTES, pk) == -1 && outlen == 0);
    CHECK(crypto_sign_open(opened, NULL, signed_message,
                           message_len + CRYPTO_BYTES, pk) == -1);
    CHECK(!faest_verify(NULL, message, message_len, pk));
    CHECK(!faest_verify(signature, NULL, 1, pk));
    CHECK(!faest_verify(signature, message, message_len, NULL));
    CHECK(!faest_verify(signature, inaccessible, SIZE_MAX, pk));
    CHECK(munmap(inaccessible, page) == 0);
    printf("lengths_and_nulls=PASS signature_bytes=%u\n", (unsigned)CRYPTO_BYTES);
}

static void check_bad_public_keys(unsigned trials)
{
    const unsigned used_bits = GREATWALL_SECRET_KEY_BITS % 8;
    const uint8_t mask = (uint8_t)(UINT8_MAX >>
        (8 * GREATWALL_FIELD_BYTES - GREATWALL_SECRET_KEY_BITS));
    for (unsigned half = 0; half < 2; ++half) {
        for (unsigned bit = used_bits; bit < 8; ++bit) {
            memcpy(pk, original_pk, CRYPTO_PUBLICKEYBYTES);
            pk[(half + 1) * GREATWALL_FIELD_BYTES - 1] |= (uint8_t)(1u << bit);
            check_public_key(0);
        }
    }
    for (unsigned trial = 0; trial < trials; ++trial) {
        uint32_t position;
        CHECK(rand_bytes((uint8_t *)&position, sizeof(position)) == 0);
        position %= 2 * GREATWALL_SECRET_KEY_BITS;
        memcpy(pk, original_pk, CRYPTO_PUBLICKEYBYTES);
        const size_t byte = (position / GREATWALL_SECRET_KEY_BITS) * GREATWALL_FIELD_BYTES +
                            (position % GREATWALL_SECRET_KEY_BITS) / 8;
        pk[byte] ^= (uint8_t)(1u << ((position % GREATWALL_SECRET_KEY_BITS) % 8));
        check_public_key(0);
        do {
            CHECK(rand_bytes(pk, CRYPTO_PUBLICKEYBYTES) == 0);
            pk[GREATWALL_FIELD_BYTES - 1] &= mask;
            pk[CRYPTO_PUBLICKEYBYTES - 1] &= mask;
        } while (!memcmp(pk, original_pk, CRYPTO_PUBLICKEYBYTES));
        check_public_key(0);
    }
    memset(pk, 0, CRYPTO_PUBLICKEYBYTES);
    check_public_key(0);
    memset(pk, 0xff, CRYPTO_PUBLICKEYBYTES);
    pk[GREATWALL_FIELD_BYTES - 1] &= mask;
    pk[CRYPTO_PUBLICKEYBYTES - 1] &= mask;
    check_public_key(0);
    memcpy(pk, original_pk, CRYPTO_PUBLICKEYBYTES);
    printf("public_keys=PASS bit_flips=%u random_canonical=%u all_padding_bits=yes\n",
           trials, trials);
}

static void check_bad_signatures(void)
{
    const size_t positions[] = {0, CRYPTO_BYTES / 2, CRYPTO_BYTES - 1};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        signature[positions[i]] ^= 1;
        restore_signed_message();
        check_public_key(0);
        signature[positions[i]] ^= 1;
    }
    restore_signed_message();
    reject_open(signed_message, message_len + CRYPTO_BYTES - 1, pk);
    signed_message[message_len + CRYPTO_BYTES] = 0;
    reject_open(signed_message, message_len + CRYPTO_BYTES + 1, pk);
    message[0] ^= 1;
    restore_signed_message();
    check_public_key(0);
    message[0] ^= 1;
    restore_signed_message();
    printf("signature_and_message_tampering=PASS\n");
}

static void check_invalid_challenge_bits(void)
{
#if ZERO_BITS_IN_CHALLENGE_3 > 0 && USE_IMPROVED_VECTOR_COMMITMENTS
    uint8_t delta[SECURITY_PARAM] = {0};
    const size_t delta_offset = VOLE_COMMIT_SIZE + VOLE_CHECK_PROOF_BYTES +
        WITNESS_BITS / 8 + QUICKSILVER_PROOF_BYTES + VECTOR_COM_OPEN_SIZE;
    const uint8_t invalid_values[] = {1, 0xff};
    size_t calls = 0;
    for (size_t bit = NONZERO_BITS_IN_CHALLENGE_3; bit < SECURITY_PARAM; ++bit) {
        for (size_t value = 0; value < sizeof(invalid_values); ++value) {
            delta[bit] = invalid_values[value];
            for (unsigned repeat = 0; repeat < 100; ++repeat) {
                allocation_attempts = 0;
                track_allocations = 1;
                const bool accepted = batch_vector_verify(block128_set_zero(),
                    NULL, delta, NULL, NULL);
                track_allocations = 0;
                CHECK(!accepted);
                CHECK(allocation_attempts == 0);
                ++calls;
            }
        }
        delta[bit] = 0;
        const size_t byte = delta_offset + bit / 8;
        const uint8_t mask = (uint8_t)(1u << (bit % 8));
        CHECK((signature[byte] & mask) == 0);
        signature[byte] |= mask;
        restore_signed_message();
        check_public_key(0);
        signature[byte] &= (uint8_t)~mask;
        restore_signed_message();
    }
    printf("invalid_challenge_bits=PASS direct_calls=%zu allocations=0 all_interfaces=reject\n",
           calls);
#else
    printf("invalid_challenge_bits=SKIP no_forced_zero_bits_or_nonbatch_mode\n");
#endif
}

static void check_empty_message(void)
{
    uint8_t nonce[SECURITY_PARAM / 8], dummy = 0;
    uint8_t *empty_signature = guarded_buffer(CRYPTO_BYTES);
    CHECK(rand_bytes(nonce, sizeof(nonce)) == 0);
    CHECK(faest_sign(empty_signature, &dummy, 0, sk, nonce, sizeof(nonce)));
    CHECK(sig_verify(pk, CRYPTO_PUBLICKEYBYTES, empty_signature, CRYPTO_BYTES, NULL, 0) == 0);
    CHECK(faest_verify(empty_signature, NULL, 0, pk));
    unsigned long long outlen = ULLONG_MAX;
    CHECK(crypto_sign_open(NULL, &outlen, empty_signature, CRYPTO_BYTES, pk) == 0);
    CHECK(outlen == 0);
    printf("empty_message=PASS\n");
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    const unsigned trials = (unsigned)strtoul(argv[2], NULL, 10);
    CHECK(trials > 0 && trials <= 1000);
    CHECK(CRYPTO_BYTES == FAEST_SIGNATURE_BYTES);
    CHECK(CRYPTO_PUBLICKEYBYTES == GREATWALL_PUBLIC_KEY_BYTES);
    uint8_t seed[64];
    for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = (uint8_t)i;
    init_random_number(&drng_algorithm, seed, sizeof(seed));
    pk = guarded_buffer(CRYPTO_PUBLICKEYBYTES);
    signature = guarded_buffer(CRYPTO_BYTES);
    signed_message = malloc(CRYPTO_BYTES + MAX_MESSAGE + 1);
    CHECK(signed_message != NULL);
    if (strcmp(argv[1], "--fresh") != 0) load_first_vector(argv[1]);
    else {
        message_len = 64;
        CHECK(rand_bytes(message, message_len) == 0);
        CHECK(crypto_sign_keypair(pk, sk) == 0);
        uint8_t nonce[SECURITY_PARAM / 8];
        CHECK(rand_bytes(nonce, sizeof(nonce)) == 0);
        CHECK(faest_sign(signature, message, message_len, sk, nonce, sizeof(nonce)));
    }
    memcpy(original_pk, pk, CRYPTO_PUBLICKEYBYTES);
    restore_signed_message();
    check_public_key(1);
    printf("valid_signature_before=PASS test_seed=bytes_00_through_3f\n");
    check_invalid_challenge_bits();
    check_lengths_and_nulls();
    check_bad_public_keys(trials);
    check_bad_signatures();
    check_public_key(1);
    check_empty_message();
    printf("valid_signature_after=PASS checks=%lu status=PASS\n", checks);
    free(signed_message);
    return 0;
}
