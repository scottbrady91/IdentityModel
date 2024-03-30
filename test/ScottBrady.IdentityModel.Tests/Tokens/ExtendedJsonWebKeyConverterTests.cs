using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Extensions;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class ExtendedJsonWebKeyConverterTests
    {
        [Fact]
        public void JsonWebKeyConverter_ConvertFromEdDsaSecurityKey()
        {
            var originKey = new EdDsaSecurityKey(EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519));
            var jwk = ExtendedJsonWebKeyConverter.ConvertFromEdDsaSecurityKey(originKey);
            Assert.NotNull(jwk);
            Assert.Equal(ExtendedSecurityAlgorithms.Curves.Ed25519, jwk.Crv);
            Assert.Equal(ExtendedSecurityAlgorithms.KeyTypes.Ecdh, jwk.Kty);
            Assert.Equal(ExtendedSecurityAlgorithms.EdDsa, jwk.Alg);
            Assert.NotNull(jwk.D);
            Assert.NotNull(jwk.X);
        }
    }
}
