using System.Text;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA
{
    public class EdDsaSignatureProviderTests
    {
        // privateKey = "FU1F1QTjYwfB-xkO6aknnBifE_Ywa94U04xpd-XJfBs"
        
        [Fact]
        public void ctor_ExpectPropertiesSet()
        {
            var expectedSecurityKey = new EdDsaSecurityKey(EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519));
            var expectedAlgorithm = ExtendedSecurityAlgorithms.EdDsa;

            var provider = new EdDsaSignatureProvider(expectedSecurityKey, expectedAlgorithm);

            provider.Key.Should().Be(expectedSecurityKey);
            provider.Algorithm.Should().Be(expectedAlgorithm);
        }

        [Fact]
        public void Sign_WhenSigningWithEd25519Curve_ExpectCorrectSignature()
        {
            const string plaintext =
                "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJ5b3UiLCJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImV4cCI6MTU5MDg0MTg4N30";
            const string expectedSignature =
                "OyBxBr344Ny-0vRCeEMLSnuEO1IecybvJBivrjum4d-dgN5WLnEAGAO43MlZeRGn1F3fRXO_xlYot68PtDuiAA";
            
            const string privateKey = "FU1F1QTjYwfB-xkO6aknnBifE_Ywa94U04xpd-XJfBs";
            var edDsaSecurityKey = new EdDsaSecurityKey(EdDsa.Create(
                new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {D = Base64UrlEncoder.DecodeBytes(privateKey)}));
            
            var signatureProvider = new EdDsaSignatureProvider(edDsaSecurityKey, ExtendedSecurityAlgorithms.EdDsa);

            var signature = signatureProvider.Sign(Encoding.UTF8.GetBytes(plaintext));

            signature.Should().BeEquivalentTo(Base64UrlEncoder.DecodeBytes(expectedSignature));
        }

        [Fact]
        public void Verify_WhenJwtSignedWithEd25519Curve_ExpectTrue()
        {
            const string plaintext =
                "eyJraWQiOiIxMjMiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJ5b3UiLCJzdWIiOiJib2IiLCJpc3MiOiJtZSIsImV4cCI6MTU5MDg0MTg4N30";
            const string signature =
                "OyBxBr344Ny-0vRCeEMLSnuEO1IecybvJBivrjum4d-dgN5WLnEAGAO43MlZeRGn1F3fRXO_xlYot68PtDuiAA";
            
            const string publicKey = "60mR98SQlHUSeLeIu7TeJBTLRG10qlcDLU4AJjQdqMQ";
            var edDsaSecurityKey = new EdDsaSecurityKey(EdDsa.Create(
                new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {X = Base64UrlEncoder.DecodeBytes(publicKey)}));

            var signatureProvider = new EdDsaSignatureProvider(edDsaSecurityKey, ExtendedSecurityAlgorithms.EdDsa);

            var isValidSignature = signatureProvider.Verify(
                Encoding.UTF8.GetBytes(plaintext),
                Base64UrlEncoder.DecodeBytes(signature));

            isValidSignature.Should().BeTrue();
        }
    }
}