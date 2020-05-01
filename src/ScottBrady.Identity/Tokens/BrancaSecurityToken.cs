using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.Identity.Tokens
{
    public class BrancaSecurityToken : SecurityToken
    {
        public BrancaSecurityToken(BrancaToken token)
        {
            try
            {
                InnerToken = new JsonWebToken("{}", token.Payload);
                IssuedAt = token.Timestamp;
            }
            catch (Exception e)
            {
                throw new ArgumentException("Branca token does contain JSON", e);
            }
        }

        public override string Id => InnerToken.Id;
        public override string Issuer => InnerToken.Issuer;
        public IEnumerable<string> Audiences => InnerToken.Audiences;
        public string Subject => InnerToken.Subject;
        public string Actor => InnerToken.Actor;
        public IEnumerable<Claim> Claims => InnerToken.Claims;

        public DateTime IssuedAt { get; }
        public override DateTime ValidFrom => InnerToken.ValidFrom; 
        public override DateTime ValidTo => InnerToken.ValidTo;
        
        internal JsonWebToken InnerToken { get; }

        public override SecurityKey SecurityKey => throw new NotSupportedException();
        public override SecurityKey SigningKey
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
    }
}