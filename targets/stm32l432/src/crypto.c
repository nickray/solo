// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
/*
 *  Wrapper for crypto implementation on device
 *
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include "util.h"
#include "crypto.h"
#include "rng.h"

#ifdef USE_SOFTWARE_IMPLEMENTATION

#include "sha256.h"
#include "uECC.h"
#include "aes.h"
#include "ctap.h"
#include "device.h"
// stuff for SHA512
#include "sha2.h"
#include "blockwise.h"
#include "tweetnacl.h"
#include "mbedtls/rsa.h"
#include APP_CONFIG
#include "log.h"
#include "memory_layout.h"


typedef enum
{
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_SECP192R1,      /*!< 192-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP224R1,      /*!< 224-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP256R1,      /*!< 256-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP384R1,      /*!< 384-bits NIST curve  */
    MBEDTLS_ECP_DP_SECP521R1,      /*!< 521-bits NIST curve  */
    MBEDTLS_ECP_DP_BP256R1,        /*!< 256-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP384R1,        /*!< 384-bits Brainpool curve */
    MBEDTLS_ECP_DP_BP512R1,        /*!< 512-bits Brainpool curve */
    MBEDTLS_ECP_DP_CURVE25519,           /*!< Curve25519               */
    MBEDTLS_ECP_DP_SECP192K1,      /*!< 192-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP224K1,      /*!< 224-bits "Koblitz" curve */
    MBEDTLS_ECP_DP_SECP256K1,      /*!< 256-bits "Koblitz" curve */
} mbedtls_ecp_group_id;


static SHA256_CTX sha256_ctx;
static cf_sha512_context sha512_ctx;
static mbedtls_rsa_context rsa2048_ctx;
static const struct uECC_Curve_t * _es256_curve = NULL;
static const uint8_t * _signing_key = NULL;
static int _key_len = 0;

// Secrets for testing only
static uint8_t master_secret[64];
static uint8_t transport_secret[32];


void crypto_sha256_init()
{
    sha256_init(&sha256_ctx);
}

void crypto_sha512_init() {
    cf_sha512_init(&sha512_ctx);
}

int rng_wrapper(void* unneeded_rng_context, unsigned char *buffer, size_t n_bytes) {
    rng_get_bytes(buffer, n_bytes);
    printf2(TAG_ERR, "generating randomness for %02x bytes\r\n", n_bytes);
    return 0;
}

void crypto_rsa2048_init() {
    mbedtls_rsa_init(&rsa2048_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    int ret = mbedtls_rsa_gen_key(
        &rsa2048_ctx,
        &rng_wrapper,
        NULL,
        2048,
        65537
    );
    printf2(TAG_ERR, "returned %02x\r\n", ret);
}

static uint8_t test_sk[64];//crypto_sign_ed25519_tweet_SECRETKEYBYTES];
// b"t\xc2\xec\xf8B\xa0\xc2A\xccp]m\xff\xde8*'\xb8\x9b\xdd\xff\xcf\xdc\xcf8\xd6\xd2\xe9\xd3\xf9}T\xc6\x99\x95\x18^\xfa \xbfz\x88\x13\x9fY 3Z\xa3\xd3\xe7\xf2\x04d4Z,\t\\vm\xfa\x15z"
static uint8_t fixed_sk[64] = {
0x74, 0xc2, 0xec, 0xf8, 0x42, 0xa0, 0xc2, 0x41, 0xcc, 0x70, 0x5d, 0x6d, 0xff, 0xde, 0x38, 0x2a, 0x27, 0xb8, 0x9b, 0xdd, 0xff, 0xcf, 0xdc, 0xcf, 0x38, 0xd6, 0xd2, 0xe9, 0xd3, 0xf9, 0x7d, 0x54, 0xc6, 0x99, 0x95, 0x18, 0x5e, 0xfa, 0x20, 0xbf, 0x7a, 0x88, 0x13, 0x9f, 0x59, 0x20, 0x33, 0x5a, 0xa3, 0xd3, 0xe7, 0xf2, 0x04, 0x64, 0x34, 0x5a, 0x2c, 0x09, 0x5c, 0x76, 0x6d, 0xfa, 0x15, 0x7a
};
static uint8_t test_pk[32];//crypto_sign_ed25519_tweet_PUBLICKEYBYTES];
static uint8_t fixed_pk[32] = {
0xc6, 0x99, 0x95, 0x18, 0x5e, 0xfa, 0x20, 0xbf, 0x7a, 0x88, 0x13, 0x9f, 0x59, 0x20, 0x33, 0x5a, 0xa3, 0xd3, 0xe7, 0xf2, 0x04, 0x64, 0x34, 0x5a, 0x2c, 0x09, 0x5c, 0x76, 0x6d, 0xfa, 0x15, 0x7a
};

void crypto_ed25519_init() {
    /* crypto_sign_keypair(&test_pk, &test_sk); */
    memmove(test_sk, fixed_sk, 64);

    /*
    uint8_t d[64];
    typedef int64_t gf[16];
    gf p[4];
    crypto_hash(d, test_sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d);
    pack(test_pk, p);

    for (int i = 0; i < 32; ++i)
        test_sk[32 + i] = test_pk[i];
    */

    memmove(test_pk, fixed_pk, 32);
}

void crypto_ed25519_sign(
    uint8_t *signed_message, size_t *signed_message_len,
    const uint8_t *message, size_t message_len//,
    /* const uint8_t *secret_key */
) {
    crypto_sign(
        signed_message, signed_message_len,
        message, message_len,
        test_sk
    );
}

void crypto_load_master_secret(uint8_t * key)
{
#if KEY_SPACE_BYTES < 96
#error "need more key bytes"
#endif
    memmove(master_secret, key, 64);
    memmove(transport_secret, key+64, 32);
}

void crypto_reset_master_secret()
{
    memset(master_secret, 0, 64);
    memset(transport_secret, 0, 32);
    ctap_generate_rng(master_secret, 64);
    ctap_generate_rng(transport_secret, 32);
}


void crypto_sha256_update(uint8_t * data, size_t len)
{
    sha256_update(&sha256_ctx, data, len);
}

void crypto_sha512_update(const uint8_t * data, size_t len) {
    cf_sha512_update(&sha512_ctx, data, len);
}

void crypto_sha256_update_secret()
{
    sha256_update(&sha256_ctx, master_secret, 32);
}

void crypto_sha256_final(uint8_t * hash)
{
    sha256_final(&sha256_ctx, hash);
}

void crypto_sha512_final(uint8_t * hash) {
    // NB: there is also cf_sha512_digest
    cf_sha512_digest_final(&sha512_ctx, hash);
}

void crypto_sha256_hmac_init(uint8_t * key, uint32_t klen, uint8_t * hmac)
{
    uint8_t buf[64];
    unsigned int i;
    memset(buf, 0, sizeof(buf));

    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret)/2;
    }
    else if (key == CRYPTO_TRANSPORT_KEY)
    {
        key = transport_secret;
        klen = 32;
    }

    if(klen > 64)
    {
        printf2(TAG_ERR, "Error, key size must be <= 64\n");
        exit(1);
    }

    memmove(buf, key, klen);

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = buf[i] ^ 0x36;
    }

    crypto_sha256_init();
    crypto_sha256_update(buf, 64);
}

void crypto_sha256_hmac_final(uint8_t * key, uint32_t klen, uint8_t * hmac)
{
    uint8_t buf[64];
    unsigned int i;
    crypto_sha256_final(hmac);
    memset(buf, 0, sizeof(buf));
    if (key == CRYPTO_MASTER_KEY)
    {
        key = master_secret;
        klen = sizeof(master_secret)/2;
    }


    if(klen > 64)
    {
        printf2(TAG_ERR, "Error, key size must be <= 64\n");
        exit(1);
    }
    memmove(buf, key, klen);

    for (i = 0; i < sizeof(buf); i++)
    {
        buf[i] = buf[i] ^ 0x5c;
    }

    crypto_sha256_init();
    crypto_sha256_update(buf, 64);
    crypto_sha256_update(hmac, 32);
    crypto_sha256_final(hmac);
}


void crypto_ecc256_init()
{
    uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
    _es256_curve = uECC_secp256r1();
}


void crypto_ecc256_load_attestation_key()
{
    static uint8_t _key [32];
    memmove(_key, (uint8_t*)ATTESTATION_KEY_ADDR, 32);
    _signing_key = _key;
    _key_len = 32;
}

void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig)
{
    if ( uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0)
    {
        printf2(TAG_ERR, "error, uECC failed\n");
        exit(1);
    }
}

void crypto_ecc256_load_key(uint8_t * data, int len, uint8_t * data2, int len2)
{
    static uint8_t privkey[32];
    generate_private_key(data,len,data2,len2,privkey);
    _signing_key = privkey;
    _key_len = 32;
}

void crypto_ecdsa_sign(uint8_t * data, int len, uint8_t * sig, int MBEDTLS_ECP_ID)
{

    const struct uECC_Curve_t * curve = NULL;

    switch(MBEDTLS_ECP_ID)
    {
        case MBEDTLS_ECP_DP_SECP192R1:
            curve = uECC_secp192r1();
            if (_key_len != 24)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP224R1:
            curve = uECC_secp224r1();
            if (_key_len != 28)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP256R1:
            curve = uECC_secp256r1();
            if (_key_len != 32)  goto fail;
            break;
        case MBEDTLS_ECP_DP_SECP256K1:
            curve = uECC_secp256k1();
            if (_key_len != 32)  goto fail;
            break;
        default:
            printf2(TAG_ERR, "error, invalid ECDSA alg specifier\n");
            exit(1);
    }

    if ( uECC_sign(_signing_key, data, len, sig, curve) == 0)
    {
        printf2(TAG_ERR, "error, uECC failed\n");
        exit(1);
    }
    return;

fail:
    printf2(TAG_ERR, "error, invalid key length\n");
    exit(1);

}

void generate_private_key(uint8_t * data, int len, uint8_t * data2, int len2, uint8_t * privkey)
{
    crypto_sha256_hmac_init(CRYPTO_MASTER_KEY, 0, privkey);
    crypto_sha256_update(data, len);
    crypto_sha256_update(data2, len2);
    crypto_sha256_update(master_secret, 32);    // TODO AES
    crypto_sha256_hmac_final(CRYPTO_MASTER_KEY, 0, privkey);

    crypto_aes256_init(master_secret + 32, NULL);
    crypto_aes256_encrypt(privkey, 32);
}


/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key, uECC_Curve curve);*/
void crypto_ecc256_derive_public_key(uint8_t * data, int len, uint8_t * x, uint8_t * y)
{
    uint8_t privkey[32];
    uint8_t pubkey[64];

    generate_private_key(data,len,NULL,0,privkey);

    memset(pubkey,0,sizeof(pubkey));
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
    memmove(x,pubkey,32);
    memmove(y,pubkey+32,32);
}

void crypto_load_external_key(uint8_t * key, int len)
{
    _signing_key = key;
    _key_len = len;
}


void crypto_ecc256_make_key_pair(uint8_t * pubkey, uint8_t * privkey)
{
    if (uECC_make_key(pubkey, privkey, _es256_curve) != 1)
    {
        printf2(TAG_ERR, "Error, uECC_make_key failed\n");
        exit(1);
    }
}

void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret)
{
    if (uECC_shared_secret(pubkey, privkey, shared_secret, _es256_curve) != 1)
    {
        printf2(TAG_ERR, "Error, uECC_shared_secret failed\n");
        exit(1);
    }

}

struct AES_ctx aes_ctx;
void crypto_aes256_init(uint8_t * key, uint8_t * nonce)
{
    if (key == CRYPTO_TRANSPORT_KEY)
    {
        AES_init_ctx(&aes_ctx, transport_secret);
    }
    else
    {
        AES_init_ctx(&aes_ctx, key);
    }
    if (nonce == NULL)
    {
        memset(aes_ctx.Iv, 0, 16);
    }
    else
    {
        memmove(aes_ctx.Iv, nonce, 16);
    }
}

// prevent round key recomputation
void crypto_aes256_reset_iv(uint8_t * nonce)
{
    if (nonce == NULL)
    {
        memset(aes_ctx.Iv, 0, 16);
    }
    else
    {
        memmove(aes_ctx.Iv, nonce, 16);
    }
}

void crypto_aes256_decrypt(uint8_t * buf, int length)
{
    AES_CBC_decrypt_buffer(&aes_ctx, buf, length);
}

void crypto_aes256_encrypt(uint8_t * buf, int length)
{
    AES_CBC_encrypt_buffer(&aes_ctx, buf, length);
}




#else
#error "No crypto implementation defined"
#endif
