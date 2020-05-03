using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoTokenHandler : JwtPayloadTokenHandler, ISecurityTokenValidator
    {
        public static readonly Dictionary<string, PasetoVersionStrategy> VersionStrategies = new Dictionary<string, PasetoVersionStrategy>
        {
            {"v2", new PasetoVersion2()}
        };
        
        public virtual bool CanReadToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
            if (token.Length > MaximumTokenSizeInBytes) return false;

            var tokenParts = token.Split(new[] {'.'}, PasetoConstants.MaxPasetoSegmentCount + 1);
            if (tokenParts.Length != 3 && tokenParts.Length != 4) return false;

            return true;
        }

        public bool CanValidateToken => true;

        public virtual string CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            throw new NotImplementedException();
        }
        
        public virtual ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            throw new NotImplementedException();
        }

        public virtual TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
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
            if (pasetoToken.Purpose == "local") pasetoSecurityToken = strategy.Decrypt(pasetoToken, validationParameters);
            else if (pasetoToken.Purpose == "public") pasetoSecurityToken = strategy.Verify(pasetoToken, validationParameters);
            else return new TokenValidationResult {Exception = new SecurityTokenException("Unsupported PASETO purpose")};
            
            
            
            
            
            
            throw new NotImplementedException();
        }
    }
}