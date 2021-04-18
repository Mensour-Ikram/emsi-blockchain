#include "hblk_crypto.h"

/**
 * ec_sign - signs a set of bytes with private key
 * @key: pointer EC_KEY to struct containing key pair
 * @msg: pointer to characters to sign
 * @msglen: length of message
 * @sig: address to store signature
 * Return: pointer to sig buffer if op succeded or NULL
 */
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg, size_t msglen,
	sig_t *sig)
{
	unsigned char md[SHA256_DIGEST_LENGTH];

	if (!key || !msg || !sig)
		return (NULL);
	if (!EC_KEY_check_key(key))
		return (NULL);
	if (!SHA256(msg, msglen, md))
		return (NULL);
	sig->len = ECDSA_size(key);
	if (!sig->len)
		return (NULL);
	if (!ECDSA_sign(0, md, SHA256_DIGEST_LENGTH, sig->sig,
				(unsigned int *)&(sig->len), (EC_KEY *)key))
		return (NULL);
	return (sig->sig);
}

