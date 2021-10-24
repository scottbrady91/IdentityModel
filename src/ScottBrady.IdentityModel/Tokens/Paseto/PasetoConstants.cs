using System;

namespace ScottBrady.IdentityModel.Tokens
{
    [Obsolete("PasetoConstants is moving to the ScottBrady.IdentityModel.Tokens.Branca package")]
    public class PasetoConstants
    {
        public const int MaxPasetoSegmentCount = 4;

        [Obsolete("PasetoConstants is moving to the ScottBrady.IdentityModel.Tokens.Branca package")]
        public class Versions
        {
            public const string V1 = "v1";
            public const string V2 = "v2";
        }
        
        [Obsolete("PasetoConstants is moving to the ScottBrady.IdentityModel.Tokens.Branca package")]
        public class Purposes
        {
            public const string Local = "local";
            public const string Public = "public";
        }
    }
}