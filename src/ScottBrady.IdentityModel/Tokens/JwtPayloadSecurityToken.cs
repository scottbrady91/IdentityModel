using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

[assembly:InternalsVisibleTo("ScottBrady.IdentityModel.Tests")]
namespace ScottBrady.IdentityModel.Tokens
{
    public abstract class JwtPayloadSecurityToken : SecurityToken
    {
        internal JwtPayloadSecurityToken() { }
        
        public JwtPayloadSecurityToken(string payload)
        {
            try
            {
                InnerToken = new JsonWebToken("{}", payload);

                using (var hasher = SHA256.Create())
                {
                    var hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(payload));
                    TokenHash = Convert.ToBase64String(hash);
                } 
            }
            catch (Exception e)
            {
                throw new ArgumentException("Token does contain valid JSON", e);
            }
        }
        
        public override string Id => InnerToken.Id;
        public override string Issuer => InnerToken.Issuer;
        public virtual IEnumerable<string> Audiences => InnerToken.Audiences;
        public virtual string Subject => InnerToken.Subject;
        public virtual string Actor => InnerToken.Actor;
        public virtual IEnumerable<Claim> Claims => InnerToken.Claims;

        public virtual DateTime IssuedAt => InnerToken.IssuedAt;
        public override DateTime ValidFrom => InnerToken.ValidFrom; 
        public override DateTime ValidTo => InnerToken.ValidTo;
        
        protected JsonWebToken InnerToken { get; }
        public virtual string TokenHash { get; }
    }
}