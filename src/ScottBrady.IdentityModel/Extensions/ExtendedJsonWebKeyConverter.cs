using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Extensions
{
    public static class ExtendedJsonWebKeyConverter
    {
        public static JsonWebKey ConvertFromEdDsaSecurityKey(EdDsaSecurityKey securityKey)
        {
            var parameters = securityKey.EdDsa.Parameters;
            return new JsonWebKey
            {
                Crv = parameters.Curve,
                X = parameters.X != null ? Base64UrlEncoder.Encode(parameters.X) : null,
                D = parameters.D != null ? Base64UrlEncoder.Encode(parameters.D) : null,
                Kty = ExtendedSecurityAlgorithms.KeyTypes.Ecdh,
                Alg = ExtendedSecurityAlgorithms.EdDsa,
                CryptoProviderFactory = securityKey.CryptoProviderFactory,
            };
        }
    }
}
