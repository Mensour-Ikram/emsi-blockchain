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
	unsigned int len;

	if (!key || !msg || !sig)
		return (NULL);
	len = sig->len;
	if (ECDSA_sign(0, msg, msglen, sig->sig, &len,
				   (EC_KEY *)key) != 1)
		return (NULL);
	sig->len = len;
	return (sig->sig);
}

