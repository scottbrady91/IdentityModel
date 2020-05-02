using System;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoTokenHandler : JwtPayloadTokenHandler, ISecurityTokenValidator
    {
        private const int MaxPasetoSegmentCount = 4;
        
        public bool CanReadToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
            if (token.Length > MaximumTokenSizeInBytes) return false;
            
            var tokenParts = token.Split(new [] { '.' }, MaxPasetoSegmentCount + 1);
            if (tokenParts.Length != 3 && tokenParts.Length != 4) return false;

            return true;
        }

        public bool CanValidateToken => true;

        public virtual string CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            throw new NotImplementedException();
        }
        
        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            throw new NotImplementedException();
        }

        public virtual TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
        {
            throw new NotImplementedException();
        }
    }
}