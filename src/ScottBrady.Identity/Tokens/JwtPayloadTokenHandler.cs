using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.Identity.Tokens
{
    public abstract class JwtPayloadTokenHandler : TokenHandler
    {
        protected virtual TokenValidationResult ValidateTokenPayload(JwtPayloadSecurityToken token, TokenValidationParameters validationParameters)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (validationParameters == null) throw new ArgumentNullException(nameof(validationParameters));

            var expires = token.ValidTo == DateTime.MinValue ? null : new DateTime?(token.ValidTo);
            var notBefore = token.ValidFrom == DateTime.MinValue ? null : new DateTime?(token.ValidFrom);
            
            Validators.ValidateLifetime(notBefore, expires, token, validationParameters);
            Validators.ValidateAudience(token.Audiences, token, validationParameters);
            Validators.ValidateIssuer(token.Issuer, token, validationParameters);
            Validators.ValidateTokenReplay(expires, token.TokenHash, validationParameters);
            
            return new TokenValidationResult
            {
                SecurityToken = token,
                ClaimsIdentity = CreateClaimsIdentity(token, validationParameters),
                IsValid = true
            };
        }
        
        protected virtual ClaimsIdentity CreateClaimsIdentity(JwtPayloadSecurityToken token, TokenValidationParameters validationParameters)
        {
            if (token == null) throw LogHelper.LogArgumentNullException(nameof(token));
            if (validationParameters == null) throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            var issuer = token.Issuer;
            if (string.IsNullOrWhiteSpace(issuer)) issuer = ClaimsIdentity.DefaultIssuer;

            var identity = validationParameters.CreateClaimsIdentity(token, issuer);
            foreach (var claim in token.Claims)
            {
                if (claim.Properties.Count == 0)
                {
                    identity.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType, issuer, issuer, identity));
                }
                else
                {
                    var mappedClaim = new Claim(claim.Type, claim.Value, claim.ValueType, issuer, issuer, identity);

                    foreach (var kv in claim.Properties)
                        mappedClaim.Properties[kv.Key] = kv.Value;

                    identity.AddClaim(mappedClaim);
                }
            }

            return identity;
        }
    }
}