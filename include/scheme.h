#ifndef SCHEME_H
#define SCHEME_H

typedef enum {
    /* Single-algorithm baselines */
    SCHEME_ECDSA_ONLY,
    SCHEME_RSA_PSS_ONLY,
    SCHEME_ML_DSA_ONLY,
    SCHEME_FALCON_ONLY,
    SCHEME_SPHINCS_ONLY,

    /* Hybrid: ECDSA + PQ */
    SCHEME_ECDSA_ML_DSA,
    SCHEME_ECDSA_FALCON,
    SCHEME_ECDSA_SPHINCS,

    /* Hybrid: RSA-PSS + PQ */
    SCHEME_RSA_PSS_ML_DSA,
    SCHEME_RSA_PSS_FALCON,
    SCHEME_RSA_PSS_SPHINCS

} scheme_t;

#endif
