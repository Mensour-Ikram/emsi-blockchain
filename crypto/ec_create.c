#include "hblk_crypto.h"
EC_KEY *ec_create(void)
{
	EC_KEY *k;

	k = EC_KEY_new_by_curve_name(EC_CURVE);

	if (k == NULL)
		return (NULL);
	else if (!EC_KEY_generate_key(k))
	{
		EC_KEY_free(k);
		return (NULL);
	}
	return (k);
}

