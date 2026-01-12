#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

static OQS_SIG *g_sig = NULL;
static uint8_t *g_pk = NULL;
static uint8_t *g_sk = NULL;

int falcon_keygen(void)
{
    g_sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    g_pk = malloc(g_sig->length_public_key);
    g_sk = malloc(g_sig->length_secret_key);
    OQS_SIG_keypair(g_sig, g_pk, g_sk);
    return 1;
}

int falcon_sign(const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len)
{
    *sig = malloc(g_sig->length_signature);
    OQS_SIG_sign(g_sig, *sig, sig_len, msg, msg_len, g_sk);
    return 1;
}

int falcon_verify(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len)
{
    (void)pubkey_len; /* liboqs already knows expected size */

    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!s)
        return -1;

    int ok = OQS_SIG_verify(s, hash, hash_len, sig, sig_len, pubkey);

    OQS_SIG_free(s);
    return (ok == OQS_SUCCESS) ? 0 : -1;
}


int falcon_get_public_key(uint8_t **out, size_t *out_len)
{
    *out = malloc(g_sig->length_public_key);
    memcpy(*out, g_pk, g_sig->length_public_key);
    *out_len = g_sig->length_public_key;
    return 1;
}
