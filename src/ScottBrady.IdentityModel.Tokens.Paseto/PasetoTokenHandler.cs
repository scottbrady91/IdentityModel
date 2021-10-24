using System.Collections.Generic;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens.Paseto
{
#pragma warning disable 618
    public class PasetoTokenHandler : ScottBrady.IdentityModel.Tokens.PasetoTokenHandler
#pragma warning restore 618
    {
        public PasetoTokenHandler(Dictionary<string, PasetoVersionStrategy> supportedVersions = null) : base(supportedVersions) { }
    }
}