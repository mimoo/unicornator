   if (EVP_VerifyFinal(ctx, sig, siglen, pubkey)) {
     /* signature valid */
   } else {
     /* signature invalid */
   }