// Copyright (c) 2016 Llamasoft

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"

// This is a bit unconventional... but hey, this is a benchmark harness, not production code
#include "libsecp256k1-config.h"
#include "secp256k1.c"


// Takes a 32 byte private key and returns a 65 or 33 byte uncompressed public key
void secp256k1_privkey_to_pubkey(secp256k1_context *ctx, unsigned char *privkey, unsigned char *pubkey, unsigned int compressed) {
    secp256k1_pubkey tmp;
    size_t pubkey_len = 65;
    unsigned int pubkey_type = ( compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED );

    // Convert the private key to an internal public key representation
    if ( !secp256k1_ec_pubkey_create(ctx, &tmp, privkey) ) { return; }

    // Convert the internal public key representation to a serialized byte format
    secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &tmp, pubkey_type);
}


// Hackishly converts an uncompressed public key to a compressed public key
// The input is considered 65 bytes, the output should be considered 33 bytes
void secp256k1_pubkey_uncomp_to_comp(unsigned char *pubkey) {
    pubkey[0] = 0x02 | (pubkey[64] & 0x01);
}



int main(int argc, char **argv) {
    // Number of iterations as 2^N
    int iter_exponent = ( argc > 1 ? atoi(argv[1]) : 18 );
    int iterations = (1 << iter_exponent);
    struct timespec clock_start;
    double clock_diff;


    // Initializing secp256k1 context
    clock_start = get_clock();
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    clock_diff = get_clockdiff_s(clock_start);
    printf("context = %12.8f\n", clock_diff);
    printf("\n");



    unsigned char privkey[32] = {
        // generated using srand(31415926), first 256 calls of rand() & 0xFF
        0xb9, 0x43, 0x14, 0xa3, 0x7d, 0x33, 0x46, 0x16, 0xd8, 0x0d, 0x62, 0x1b, 0x11, 0xa5, 0x9f, 0xdd,
        0x13, 0x56, 0xf6, 0xec, 0xbb, 0x9e, 0xb1, 0x9e, 0xfd, 0xe6, 0xe0, 0x55, 0x43, 0xb4, 0x1f, 0x30
    };

    printf("iterations = 2^%d (%d)\n", iter_exponent, iterations);

    unsigned char pubkey[65];
    clock_start = get_clock();
    for (size_t iter = 0; iter < iterations; iter++) {
        secp256k1_privkey_to_pubkey(ctx, privkey, pubkey, 0);
    }
    clock_diff = get_clockdiff_s(clock_start);

    printf("pubkey total = %12.8f\n", clock_diff);
    printf("pubkey avg   = %12.8f\n", clock_diff / iterations);
    printf("pubkey/sec   = %12.2f\n", iterations / clock_diff);
    printf("\n");


    // Visually inspect public key contents
    // pubkey (u) = 04faf45a131fe316e7597817f532140d75bbc2b7dcd61835eabc29fa5d7f802551e5ae5b10cfc9970c0dcaa1ab7dc1b340bc5b3df687a5bce72667fd6ce6c36629
    printf("pubkey (u) = ");
    for (int i = 0; i < 65; i++) { printf("%02x", pubkey[i] & 0xFF); }
    printf("\n");

    // pubkey (c) = 03faf45a131fe316e7597817f532140d75bbc2b7dcd61835eabc29fa5d7f802551
    printf("pubkey (c) = ");
    secp256k1_pubkey_uncomp_to_comp(pubkey);
    for (int i = 0; i < 33; i++) { printf("%02x", pubkey[i] & 0xFF); }
    printf("\n");


    return 0;
}