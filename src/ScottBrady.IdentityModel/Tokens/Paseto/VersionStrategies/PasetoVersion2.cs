using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoVersion2 : PasetoVersionStrategy
    {
        public override PasetoSecurityToken Decrypt(PasetoToken token, TokenValidationParameters validationParameters)
        {
            throw new System.NotImplementedException();
        }

        public override PasetoSecurityToken Verify(PasetoToken token, TokenValidationParameters validationParameters)
        {
            // extract header (e.g. "v2.public.")
            
            // check version
            
            // check purpose
            
            // decode payload
            
            // extract signature from payload (leftmost 64 bytes)
            
            // extract message from payload
            
            // pack header, message and footer (using PAE?)
            
            // verify signature
            
            throw new System.NotImplementedException();
        }
    }
}