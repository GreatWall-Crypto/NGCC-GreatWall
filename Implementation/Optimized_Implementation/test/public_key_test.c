#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "api.h"
#include "faest.h"
#include "randomness.h"

enum { TRIALS = 100, MESSAGE_BYTES = 64, MAX_FLIPS = 8 };

typedef struct
{
    unsigned accepted;
    unsigned rejected;
    unsigned errors;
    unsigned canonical;
} test_counts;

int rand_bytes(uint8_t *out, size_t len)
{
    while (len)
    {
        const ssize_t got = getrandom(out, len, 0);
        if (got < 0)
        {
            if (errno == EINTR) continue;
            return -1;
        }
        if (got == 0) return -1;
        out += (size_t)got;
        len -= (size_t)got;
    }
    return 0;
}

static int random_below(uint32_t bound, uint32_t *out)
{
    const uint32_t threshold = (uint32_t)(0u - bound) % bound;
    uint32_t value;
    do
    {
        if (rand_bytes((uint8_t *)&value, sizeof(value)) != 0) return -1;
    } while (value < threshold);
    *out = value % bound;
    return 0;
}

static uint8_t public_key_top_mask(void)
{
    return UINT8_MAX >> (8 * GREATWALL_FIELD_BYTES - GREATWALL_SECRET_KEY_BITS);
}

static bool canonical_encoding(const uint8_t *pk)
{
    return ((pk[GREATWALL_FIELD_BYTES - 1] |
             pk[GREATWALL_PUBLIC_KEY_BYTES - 1]) &
            (uint8_t)~public_key_top_mask()) == 0;
}

static void canonicalize_public_key(uint8_t *pk)
{
    pk[GREATWALL_FIELD_BYTES - 1] &= public_key_top_mask();
    pk[GREATWALL_PUBLIC_KEY_BYTES - 1] &= public_key_top_mask();
}

static void print_hex(FILE *out, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) fprintf(out, "%02x", data[i]);
}

static int flip_public_key(uint8_t *candidate, const uint8_t *original,
                           bool canonical, unsigned *flips)
{
    uint32_t selected[MAX_FLIPS], count;
    const uint32_t available = canonical
        ? 2u * GREATWALL_SECRET_KEY_BITS : 8u * GREATWALL_PUBLIC_KEY_BYTES;
    if (random_below(MAX_FLIPS, &count) != 0) return -1;
    ++count;
    memcpy(candidate, original, GREATWALL_PUBLIC_KEY_BYTES);
    for (uint32_t i = 0; i < count; ++i)
    {
        uint32_t position;
        bool duplicate;
        do
        {
            if (random_below(available, &position) != 0) return -1;
            duplicate = false;
            for (uint32_t j = 0; j < i; ++j)
                if (selected[j] == position) duplicate = true;
        } while (duplicate);
        selected[i] = position;
        const size_t byte = canonical
            ? (position / GREATWALL_SECRET_KEY_BITS) * GREATWALL_FIELD_BYTES +
              (position % GREATWALL_SECRET_KEY_BITS) / 8
            : position / 8;
        const unsigned bit = canonical
            ? (position % GREATWALL_SECRET_KEY_BITS) % 8 : position % 8;
        candidate[byte] ^= (uint8_t)(1u << bit);
    }
    *flips = count;
    return 0;
}

static int random_public_key(uint8_t *candidate, const uint8_t *original,
                             bool canonical)
{
    do
    {
        if (rand_bytes(candidate, GREATWALL_PUBLIC_KEY_BYTES) != 0) return -1;
        if (canonical) canonicalize_public_key(candidate);
    } while (memcmp(candidate, original, GREATWALL_PUBLIC_KEY_BYTES) == 0);
    return 0;
}

static int verify(const uint8_t *pk, const uint8_t *signed_message,
                  unsigned long long signed_len, const uint8_t *message,
                  int *api_return)
{
    uint8_t opened[MESSAGE_BYTES];
    unsigned long long opened_len = 0;
    *api_return = crypto_sign_open(opened, &opened_len,
                                  signed_message, signed_len, pk);
    if (*api_return == -1) return 0;
    if (*api_return != 0 || opened_len != MESSAGE_BYTES ||
        memcmp(opened, message, MESSAGE_BYTES) != 0) return -1;
    return 1;
}

static void record_case(FILE *details, const char *group, unsigned trial,
                        bool canonical_mode, unsigned flips, const uint8_t *pk,
                        int outcome, int api_return, test_counts *counts)
{
    const bool canonical = canonical_encoding(pk);
    if (outcome == 1) ++counts->accepted;
    else if (outcome == 0) ++counts->rejected;
    else ++counts->errors;
    if (canonical) ++counts->canonical;
    fprintf(details,
            "%s trial=%03u mode=%s flips=%u encoding=%s result=%s api_return=%d pk=",
            group, trial, canonical_mode ? "canonical" : "raw", flips,
            canonical ? "canonical" : "noncanonical",
            outcome == 1 ? "ACCEPT" : outcome == 0 ? "REJECT" : "ERROR",
            api_return);
    print_hex(details, pk, GREATWALL_PUBLIC_KEY_BYTES);
    fputc('\n', details);
}

static void print_summary(const char *group, const test_counts *counts)
{
    printf("%s: trials=%u accepted=%u rejected=%u errors=%u "
           "canonical_encoding=%u noncanonical_encoding=%u\n",
           group, TRIALS, counts->accepted, counts->rejected, counts->errors,
           counts->canonical, TRIALS - counts->canonical);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s CASE_DETAILS_LOG\n", argv[0]);
        return 2;
    }
    FILE *details = fopen(argv[1], "w");
    if (!details)
    {
        perror("open case details");
        return 2;
    }
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    uint8_t candidate[CRYPTO_PUBLICKEYBYTES], message[MESSAGE_BYTES];
    uint8_t *signed_message = malloc(MESSAGE_BYTES + CRYPTO_BYTES);
    int result = 2, api_return;
    unsigned long long signed_len = 0;
    test_counts flips = {0}, fake = {0};
    if (!signed_message) goto done;

    printf("Algorithm: %s\n", CRYPTO_ALGNAME);
#ifdef GREATWALL_HASH_BACKEND_SM3
    puts("Hash backend: SM3");
#else
    puts("Hash backend: SHAKE");
#endif
    printf("Public key: %u bytes; field: %u bits; RNG: Linux getrandom\n",
           (unsigned)GREATWALL_PUBLIC_KEY_BYTES, (unsigned)GREATWALL_SECRET_KEY_BITS);
    puts("Each group: 50 canonical-encoding trials + 50 raw-encoding trials.");
    if (rand_bytes(message, sizeof(message)) != 0 ||
        crypto_sign_keypair(pk, sk) != 0 ||
        crypto_sign(signed_message, &signed_len, message, sizeof(message), sk) != 0 ||
        signed_len != MESSAGE_BYTES + CRYPTO_BYTES)
    {
        fputs("ERROR: random generation, key generation or signing failed.\n", stderr);
        goto done;
    }

    fprintf(details, "original_pk=");
    print_hex(details, pk, sizeof(pk));
    fprintf(details, "\nmessage=");
    print_hex(details, message, sizeof(message));
    fprintf(details, "\nsignature=");
    print_hex(details, signed_message + MESSAGE_BYTES, CRYPTO_BYTES);
    fputc('\n', details);

    if (verify(pk, signed_message, signed_len, message, &api_return) != 1)
    {
        printf("Original public key: FAIL (api_return=%d)\n", api_return);
        result = 1;
        goto done;
    }
    puts("Original public key: PASS");

    for (unsigned trial = 0; trial < TRIALS; ++trial)
    {
        unsigned count;
        const bool canonical = trial < TRIALS / 2;
        if (flip_public_key(candidate, pk, canonical, &count) != 0) goto rng_error;
        const int outcome = verify(candidate, signed_message, signed_len,
                                   message, &api_return);
        record_case(details, "bit_flip", trial + 1, canonical, count, candidate,
                    outcome, api_return, &flips);
    }
    print_summary("Bit-flipped public keys", &flips);

    for (unsigned trial = 0; trial < TRIALS; ++trial)
    {
        const bool canonical = trial < TRIALS / 2;
        if (random_public_key(candidate, pk, canonical) != 0) goto rng_error;
        const int outcome = verify(candidate, signed_message, signed_len,
                                   message, &api_return);
        record_case(details, "random_fake", trial + 1, canonical, 0, candidate,
                    outcome, api_return, &fake);
    }
    print_summary("Random fake public keys", &fake);

    const int valid_again = verify(pk, signed_message, signed_len, message, &api_return);
    printf("Original public key after all trials: %s\n", valid_again == 1 ? "PASS" : "FAIL");
    result = flips.accepted == 0 && fake.accepted == 0 &&
             flips.errors == 0 && fake.errors == 0 &&
             flips.rejected == TRIALS && fake.rejected == TRIALS &&
             valid_again == 1 ? 0 : 1;
    printf("Overall: %s\n", result == 0 ? "PASS" : "FAIL");
    goto done;

rng_error:
    fputs("ERROR: Linux getrandom failed during a trial.\n", stderr);
done:
    free(signed_message);
    if (fclose(details) != 0) result = 2;
    return result;
}

