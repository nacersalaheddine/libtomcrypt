int crypto_sign(
  unsigned char *sm,unsigned long long *smlen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk, const unsigned char *pk
)
{
  /* unsigned char pk[32]; */
  unsigned char az[64];
  unsigned char nonce[64];
  unsigned char hram[64];
  ge_p3 R;
  unsigned long len;
  int err, hash_idx;

  /* memmove(pk,sk + 32,32); */

  /* crypto_hash_sha512(az,sk,32); */
  hash_idx = find_hash("sha512");
  len = sizeof(az);
  if ((err = hash_memory(hash_idx, sk, 32, az, &len)) != CRYPT_OK) return err;
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  *smlen = mlen + 64;
  memmove(sm + 64,m,mlen);
  memmove(sm + 32,az + 32,32);
  /* crypto_hash_sha512(nonce,sm + 32,mlen + 32); */
  len = sizeof(nonce);
  if ((err = hash_memory(hash_idx, sm + 32, mlen + 32, nonce, &len)) != CRYPT_OK) return err;
  memmove(sm + 32,pk,32);

  sc_reduce(nonce);
  ge_scalarmult_base(&R,nonce);
  ge_p3_tobytes(sm,&R);

  /* crypto_hash_sha512(hram,sm,mlen + 64); */
  len = sizeof(hram);
  if ((err = hash_memory(hash_idx, sm, mlen + 64, hram, &len)) != CRYPT_OK) return err;
  sc_reduce(hram);
  sc_muladd(sm + 32,hram,az,nonce);

  return CRYPT_OK;
}
