using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens.Branca
{
    [Obsolete("Branca support is now deprecated. Please reach out via GitHub if you would like to see this feature maintained.")]
    public class BrancaSecurityToken : JwtPayloadSecurityToken
    {
        public BrancaSecurityToken(BrancaToken token) : base(Encoding.UTF8.GetString(token.Payload))
        {
            IssuedAt = token.Timestamp;
        }

        public override DateTime IssuedAt { get; }

        public override SecurityKey SecurityKey => throw new NotSupportedException();
        public override SecurityKey SigningKey
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
    }
}