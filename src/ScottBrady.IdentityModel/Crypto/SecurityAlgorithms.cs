namespace ScottBrady.IdentityModel.Crypto
{
    public static class SecurityAlgorithms
    {
        // https://tools.ietf.org/html/draft-amringer-jose-chacha-02#section-4.1
        public const string XChaCha20Poly1305 = "XC20P";

        // https://tools.ietf.org/html/rfc8037#section-5
        public const string EdDSA = "EdDSA";
    }
}