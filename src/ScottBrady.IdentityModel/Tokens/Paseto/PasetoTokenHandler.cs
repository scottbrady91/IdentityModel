using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoTokenHandler : JwtPayloadTokenHandler
    {
        public static readonly Dictionary<string, PasetoVersionStrategy> VersionStrategies = new Dictionary<string, PasetoVersionStrategy>
        {
            {"v2", new PasetoVersion2()}
        };
        
        public override bool CanReadToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
            if (token.Length > MaximumTokenSizeInBytes) return false;

            var tokenParts = token.Split(new[] {'.'}, PasetoConstants.MaxPasetoSegmentCount + 1);
            if (tokenParts.Length != 3 && tokenParts.Length != 4) return false;

            return true;
        }

        public virtual string CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            throw new NotImplementedException();
        }
        
        public override TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(token)) return new TokenValidationResult {Exception = new ArgumentNullException(nameof(token))};
            if (validationParameters == null) return new TokenValidationResult {Exception = new ArgumentNullException(nameof(validationParameters))};
            if (!CanReadToken(token)) return new TokenValidationResult {Exception = new SecurityTokenException("Unable to read token")};

            var pasetoToken = new PasetoToken(token);
            
            // get strategy for version + purpose
            if (!VersionStrategies.TryGetValue(pasetoToken.Version, out var strategy))
            {
                return new TokenValidationResult {Exception = new SecurityTokenException("Unsupported PASETO version")};
            }
            
            PasetoSecurityToken pasetoSecurityToken;
            try
            {
                if (pasetoToken.Purpose == "local")
                {
                    var keys = GetDecryptionKeys(token, validationParameters);
                    pasetoSecurityToken = strategy.Decrypt(pasetoToken, keys);
                }
                else if (pasetoToken.Purpose == "public")
                {
                    var keys = GetSigningKeys(token, validationParameters);
                
                    // TODO: kid handling (footer?)
                
                    pasetoSecurityToken = strategy.Verify(pasetoToken, keys);
                }
                else
                {
                    return new TokenValidationResult {Exception = new SecurityTokenException("Unsupported PASETO purpose")};
                }
            }
            catch (Exception e)
            {
                return new TokenValidationResult {Exception = e};
            }
            
            var innerValidationResult = ValidateTokenPayload(pasetoSecurityToken, validationParameters);
            if (!innerValidationResult.IsValid) return innerValidationResult;

            var identity = innerValidationResult.ClaimsIdentity;
            if (validationParameters.SaveSigninToken) identity.BootstrapContext = token;

            return new TokenValidationResult
            {
                SecurityToken = pasetoSecurityToken,
                ClaimsIdentity = identity,
                IsValid = true
            };
        }
    }
}