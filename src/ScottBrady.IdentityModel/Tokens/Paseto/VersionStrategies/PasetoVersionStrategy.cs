using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public abstract class PasetoVersionStrategy
    {
        /// <summary>
        /// Decrypts a local token
        /// </summary>
        public abstract PasetoSecurityToken Decrypt(PasetoToken token, TokenValidationParameters validationParameters);
        
        /// <summary>
        /// Verifies the a public token's signature 
        /// </summary>
        public abstract PasetoSecurityToken Verify(PasetoToken token, TokenValidationParameters validationParameters);
    }
}