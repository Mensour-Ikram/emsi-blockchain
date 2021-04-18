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
	uint32_t len = 0;

	if (!key || !msg || !msglen)
		return (NULL);

	memset(sig->sig, 0, sizeof(sig->sig));
	if (!ECDSA_sign(0, msg, (int)msglen, sig->sig, &len, (EC_KEY *)key))
	{
		sig->len = 0;
		return (NULL);
	}
	sig->len = (uint8_t)len;
	return (sig->sig);
}

