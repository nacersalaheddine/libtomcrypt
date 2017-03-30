/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"

/**
  @file der_length_utctime.c
  ASN.1 DER, get length of GeneralizedTime, Steffen Jaeckel
  Based on der_length_utctime.c
*/

#ifdef LTC_DER

/**
  Gets length of DER encoding of GeneralizedTime
  @param utctime      The UTC time structure to get the size of
  @param outlen [out] The length of the DER encoding
  @return CRYPT_OK if successful
*/
int der_length_generalizedtime(ltc_generalizedtime *gtime, unsigned long *outlen)
{
   LTC_ARGCHK(outlen  != NULL);
   LTC_ARGCHK(gtime != NULL);

   if (gtime->fs == 0) {
      /* we encode as YYYYMMDDhhmmssZ */
      *outlen = 2 + 15;
   } else {
      /* we encode as YYYYMMDDhhmmss.fsZ */
      unsigned long len = 2 + 17;
      unsigned fs = gtime->fs;
      do {
         fs /= 10;
         len++;
      } while(fs != 0);
      *outlen = len;
   }

   return CRYPT_OK;
}

#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
