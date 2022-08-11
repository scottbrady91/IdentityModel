using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens.Paseto
{
    public class PasetoVersion4 : PasetoEdDsaBase
    {
        protected override string Version => PasetoConstants.Versions.V4;
        protected override string PublicHeader => "v4.public.";
        
        protected override byte[] PackToken(byte[] payload, byte[] footer = null, string implicitAssertion = null)
        {
            return PreAuthEncode(new[]
            {
                Encoding.UTF8.GetBytes(PublicHeader),
                payload,
                footer,
                Encoding.UTF8.GetBytes(implicitAssertion ?? string.Empty)
            });
        }
        
        public override string Encrypt(string payload, string footer, EncryptingCredentials encryptingCredentials)
        {
            throw new NotSupportedException("v4.local not supported");
        }

        public override PasetoSecurityToken Decrypt(PasetoToken token, IEnumerable<SecurityKey> decryptionKeys)
        {
            throw new NotSupportedException("v4.local not supported");
        }
    }
}