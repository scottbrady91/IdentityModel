using System;

namespace ScottBrady.IdentityModel.Tokens.Paseto
{
    [Obsolete("PASETO support is now deprecated. Please reach out via GitHub if you would like to see this feature maintained.")]
    public class PasetoConstants
    {
        public const int MaxPasetoSegmentCount = 4;

        public class Versions
        {
            public const string V1 = "v1";
            public const string V2 = "v2";
        }
        
        public class Purposes
        {
            public const string Local = "local";
            public const string Public = "public";
        }
    }
}