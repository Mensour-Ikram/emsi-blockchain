#ifndef HBLK_CRYPTO_H
#define HBLK_CRYPTO_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#define PUB_FILENAME	"key_pub.pem"
#define PRI_FILENAME	"key.pem"
#define EC_CURVE	NID_secp256k1

/* EC_KEY public key octet string length (using 256-bit curve) */
#define EC_PUB_LEN	65
/* Maximum signature octet string length (using 256-bit curve) */
#define SIG_MAX_LEN

uint8_t *sha256(int8_t const *s, size_t len,
	uint8_t digest[SHA256_DIGEST_LENGTH]);
EC_KEY *ec_create(void);
#endif /* HBLK_CRYPTO_H */

