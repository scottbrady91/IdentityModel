namespace ScottBrady.IdentityModel.Crypto;

public static class ExtendedSecurityAlgorithms
{
    // https://tools.ietf.org/html/draft-amringer-jose-chacha-02#section-4.1
    public const string ChaCha20Poly1305 = "C20P";
    public const string XChaCha20Poly1305 = "XC20P";
    public const string ChaCha20Poly1305KeyWrap = "C20PKW";
    public const string XChaCha20Poly1305KeyWrap = "XC20PKW";
    public const string EchdEsWithChaCha20Poly1305 = "ECDH-ES+C20PKW";
    public const string EchdEsWithXChaCha20Poly1305 = "ECDH-ES+XC20PKW";

    // https://tools.ietf.org/html/rfc8037#section-5
    public const string EdDsa = "EdDSA";

    public class Curves
    {
        // https://tools.ietf.org/html/rfc8037#section-5
        public const string Ed25519 = "Ed25519";
        public const string Ed448 = "Ed448";
        public const string X25519 = "X25519";
        public const string X448 = "X448";
    }
}