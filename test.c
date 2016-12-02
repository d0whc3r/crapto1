#include "crapto1.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
    struct Crypto1State *revstate;
    uint64_t lfsr;
    unsigned char *plfsr = (unsigned char *) &lfsr;

    if (argc < 6) {
        // Tell the user how to run the program
        printf("[?] Usage: %s <Tag UID> <Tag challenge (nt)> <Reader challenge, encrypted (nr xor ks1, aka nr)> <Reader response, encrypted (ar XOR ks2, aka ar)> <Tag response, encrypted (at XOR ks3, aka at)>\n",
               argv[0]);
        /* "Usage messages" are a conventional way of telling the user
         * how to run a program if they enter the command incorrectly.
         */
        return 1;
    }

    uint32_t uid = (uint32_t) argv[1];
    uint32_t tag_challenge = (uint32_t) argv[2];
    uint32_t nr_enc = (uint32_t) argv[3];
    uint32_t reader_response = (uint32_t) argv[4];
    uint32_t tag_response = (uint32_t) argv[5];

    uint32_t ks2 = reader_response ^prng_successor(tag_challenge, 64);
    uint32_t ks3 = tag_response ^prng_successor(tag_challenge, 96);

    printf("nt' : %08x\n", prng_successor(tag_challenge, 64));
    printf("nt'': %08x\n", prng_successor(tag_challenge, 96));

    printf("ks2 : %08x\n", ks2);
    printf("ks3 : %08x\n", ks3);

    revstate = lfsr_recovery64(ks2, ks3);

    lfsr_rollback_word(revstate, 0, 0);
    lfsr_rollback_word(revstate, 0, 0);
    lfsr_rollback_word(revstate, nr_enc, 1);
    lfsr_rollback_word(revstate, uid ^ tag_challenge, 0);
    crypto1_get_lfsr(revstate, &lfsr);
    printf("Found Key: [%02x %02x %02x %02x %02x %02x]\n\n", plfsr[5], plfsr[4], plfsr[3], plfsr[2], plfsr[1],
           plfsr[0]);

    return 0;
}
