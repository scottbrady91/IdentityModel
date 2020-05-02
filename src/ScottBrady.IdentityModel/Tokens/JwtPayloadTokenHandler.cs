using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public abstract class JwtPayloadTokenHandler : TokenHandler
    {
        /// <summary>
        /// Validates a tokens lifetime, audience, and issuer using JWT payload validation rules.
        /// Also checks for token replay
        /// </summary>
        protected virtual TokenValidationResult ValidateTokenPayload(JwtPayloadSecurityToken token, TokenValidationParameters validationParameters)
        {
            if (token == null) return new TokenValidationResult {Exception = new ArgumentNullException(nameof(token))};
            if (validationParameters == null) return new TokenValidationResult {Exception = new ArgumentNullException(nameof(validationParameters))};

            var expires = token.ValidTo == DateTime.MinValue ? null : new DateTime?(token.ValidTo);
            var notBefore = token.ValidFrom == DateTime.MinValue ? null : new DateTime?(token.ValidFrom);

            try
            {
                ValidateLifetime(notBefore, expires, token, validationParameters);
                ValidateAudience(token.Audiences, token, validationParameters);
                ValidateIssuer(token.Issuer, token, validationParameters);
                ValidateTokenReplay(expires, token.TokenHash, validationParameters);
            }
            catch (Exception e)
            {
                return new TokenValidationResult {Exception = e};
            }
            
            return new TokenValidationResult
            {
                SecurityToken = token,
                ClaimsIdentity = CreateClaimsIdentity(token, validationParameters),
                IsValid = true
            };
        }
        
        protected virtual void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
            => Validators.ValidateLifetime(notBefore, expires, securityToken, validationParameters);

        protected virtual void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
            => Validators.ValidateAudience(audiences, securityToken, validationParameters);

        protected virtual string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
            => Validators.ValidateIssuer(issuer, securityToken, validationParameters);

        protected virtual void ValidateTokenReplay(DateTime? expirationTime, string securityToken, TokenValidationParameters validationParameters)
            => Validators.ValidateTokenReplay(expirationTime, securityToken, validationParameters);

        protected virtual void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
            => Validators.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        
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