int crypto_sk_to_pk(unsigned char *pk, const unsigned char *sk)
{
  unsigned char az[64];
  ge_p3 A;
  unsigned long len;
  int err, hash_idx;

  /* crypto_hash_sha512(az,sk,32); */
  hash_idx = find_hash("sha512");
  len = sizeof(az);
  if ((err = hash_memory(hash_idx, sk, 32, az, &len)) != CRYPT_OK) return err;
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  ge_scalarmult_base(&A,az);
  ge_p3_tobytes(pk,&A);

  return CRYPT_OK;
}

int crypto_sign_keypair(prng_state *prng, int wprng, unsigned char *pk,unsigned char *sk)
{
  int err;

  /* randombytes(sk,32); */
  if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
     return err;
  }

  if (prng_descriptor[wprng].read(sk,32, prng) != 32) {
     return CRYPT_ERROR_READPRNG;
  }

  err = crypto_sk_to_pk(sk, pk);

  /* memmove(sk + 32,pk,32);
   * we don't copy the pk in the sk */
  return err;
}
