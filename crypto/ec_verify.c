#include "hblk_crypto.h"

/**
 * ec_verify - verifies a message with public key
 * @key: pointer to struct containing key pair
 * @msg: the message to sign
 * @msglen: length of message
 * @sig: address to store signature
 * Return: 1 if verified else 0
 */
int ec_verify(EC_KEY const *key, uint8_t const *msg, size_t msglen,
	sig_t const *sig)
{

	if (!key || !msg || !sig)
		return (0);
	if (!EC_KEY_check_key(key))
		return (0);
	if (ECDSA_verify(0, msg, msglen, sig->sig, sig->len,
				(EC_KEY *)key) == 1)
		return (1);
	return (0);
}

