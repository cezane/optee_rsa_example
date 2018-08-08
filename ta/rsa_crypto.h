#ifndef RSA_CRYPTO_H
#define RSA_CRYPTO_H

// prototypes
BOOLEAN encrypt(char *plan, int plan_len, char *ciph, int *ciph_len);
BOOLEAN decrypt(char *ciph, int ciph_len, char *plan, int *plan_len);

#endif
