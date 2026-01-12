#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

static OQS_SIG *g_sig = NULL;
static uint8_t *g_pk = NULL;
static uint8_t *g_sk = NULL;

int dilithium_keygen(void)
{
    g_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    g_pk = malloc(g_sig->length_public_key);
    g_sk = malloc(g_sig->length_secret_key);
    OQS_SIG_keypair(g_sig, g_pk, g_sk);
    return 1;
}

int dilithium_sign(const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len)
{
    *sig = malloc(g_sig->length_signature);
    OQS_SIG_sign(g_sig, *sig, sig_len, msg, msg_len, g_sk);
    return 1;
}

int dilithium_verify(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk, size_t pk_len)
{
    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    int ok = OQS_SIG_verify(s, hash, hash_len, sig, sig_len, pk);
    OQS_SIG_free(s);
    return (ok == OQS_SUCCESS) ? 0 : -1;
}


int dilithium_get_public_key(uint8_t **out, size_t *out_len)
{
    *out = malloc(g_sig->length_public_key);
    memcpy(*out, g_pk, g_sig->length_public_key);
    *out_len = g_sig->length_public_key;
    return 1;
}
