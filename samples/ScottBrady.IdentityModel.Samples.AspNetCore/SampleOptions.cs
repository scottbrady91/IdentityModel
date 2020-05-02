using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using SecurityAlgorithms = ScottBrady.IdentityModel.Crypto.SecurityAlgorithms;

namespace ScottBrady.IdentityModel.Samples.AspNetCore
{
    public class SampleOptions
    {
        private EncryptingCredentials encryptingCredentials;

        public EncryptingCredentials EncryptingCredentials
        {
            get
            {
                if (encryptingCredentials == null)
                {
                    var key = new byte[32];
                    RandomNumberGenerator.Create().GetBytes(key);

                    encryptingCredentials = new EncryptingCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.XChaCha20Poly1305);
                }
                
                return encryptingCredentials;
            }
        }
    }
}