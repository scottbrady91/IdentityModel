using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Samples.AspNetCore
{
    public class SampleOptions
    {
        private EncryptingCredentials encryptingCredentials;

        public EncryptingCredentials BrancaEncryptingCredentials
        {
            get
            {
                if (encryptingCredentials == null)
                {
                    var key = new byte[32];
                    RandomNumberGenerator.Create().GetBytes(key);

                    encryptingCredentials = new EncryptingCredentials(
                        new SymmetricSecurityKey(key),
                        ExtendedSecurityAlgorithms.XChaCha20Poly1305);
                }
                
                return encryptingCredentials;
            }
        }
        
        public RsaSecurityKey PasetoV1PrivateKey = new RsaSecurityKey(RSA.Create());
        public RsaSecurityKey PasetoV1PublicKey => new RsaSecurityKey(RSA.Create(PasetoV1PrivateKey.Rsa.ExportParameters(false)));

        public readonly EdDsaSecurityKey PasetoV2PublicKey = new EdDsaSecurityKey(
            EdDsa.CreateFromPublicKey(Convert.FromBase64String("doaS7QILHBdnPULlgs1fX0MWpd1wak14r1yT6ae/b4M="), ExtendedSecurityAlgorithms.Curves.Ed25519));
        
        public readonly EdDsaSecurityKey PasetoV2PrivateKey= new EdDsaSecurityKey(
                EdDsa.CreateFromPrivateKey(Convert.FromBase64String("doaS7QILHBdnPULlgs1fX0MWpd1wak14r1yT6ae/b4M="), ExtendedSecurityAlgorithms.Curves.Ed25519));
    }
}