using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens.Paseto
{
    public abstract class PasetoVersionStrategy
    {
        /// <summary>
        /// Creates an encrypted local token 
        /// </summary>
        public abstract string Encrypt(string payload, string footer, EncryptingCredentials encryptingCredentials);

        /// <summary>
        /// Creates a signed public token 
        /// </summary>
        public abstract string Sign(string payload, string footer, SigningCredentials signingCredentials);
        
        /// <summary>
        /// Decrypts a local token
        /// </summary>
        public abstract PasetoSecurityToken Decrypt(PasetoToken token, IEnumerable<SecurityKey> decryptionKeys);
        
        /// <summary>
        /// Verifies the a public token's signature 
        /// </summary>
        public abstract PasetoSecurityToken Verify(PasetoToken token, IEnumerable<SecurityKey> signingKeys);
        
        protected static byte[] PreAuthEncode(IReadOnlyList<byte[]> pieces)
        {
            if (pieces == null) throw new ArgumentNullException(nameof(pieces));
            
            var output = BitConverter.GetBytes((long) pieces.Count);

            foreach (var piece in pieces)
            {
                output = output.Combine(BitConverter.GetBytes((long) piece.Length), piece);
            }

            return output.ToArray();
        }
    }
}