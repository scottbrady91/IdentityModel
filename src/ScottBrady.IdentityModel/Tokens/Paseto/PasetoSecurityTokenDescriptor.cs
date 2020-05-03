using System;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens
{
    public class PasetoSecurityTokenDescriptor : SecurityTokenDescriptor
    {
        public PasetoSecurityTokenDescriptor(string version, string purpose)
        {
            if (string.IsNullOrWhiteSpace(version)) throw new ArgumentNullException(nameof(version));
            if (string.IsNullOrWhiteSpace(purpose)) throw new ArgumentNullException(nameof(purpose));

            Version = version;
            Purpose = purpose;
        }
        
        public string Version { get; }
        public string Purpose { get; }
    }
}