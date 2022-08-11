namespace ScottBrady.IdentityModel.Tokens.Paseto
{
    public class PasetoConstants
    {
        public const int MaxPasetoSegmentCount = 4;

        public class Versions
        {
            public const string V1 = "v1";
            public const string V2 = "v2";
            public const string V4 = "v4";
        }
        
        public class Purposes
        {
            public const string Local = "local";
            public const string Public = "public";
        }

        public const string ImplicitAssertionKey = "implicit-assertion";
    }
}