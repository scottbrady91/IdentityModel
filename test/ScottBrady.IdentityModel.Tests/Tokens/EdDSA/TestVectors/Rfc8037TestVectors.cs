using System.Text;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA
{
    public class Rfc8037TestVectors
    {
        private readonly byte[] privateKey = Base64UrlEncoder.DecodeBytes("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
        private readonly byte[] publicKey = Base64UrlEncoder.DecodeBytes("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        
        [Fact]
        public void A_4_Ed25519_Signing()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc");
            byte[] expectedSignature = Base64UrlEncoder.DecodeBytes("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");

            var signatureProvider = new EdDsaSignatureProvider(
                new EdDsaSecurityKey(EdDsa.CreateFromPrivateKey(privateKey, ExtendedSecurityAlgorithms.Curves.Ed25519)),
                ExtendedSecurityAlgorithms.EdDsa);

            signatureProvider.Sign(plaintext).Should().BeEquivalentTo(expectedSignature);
        }

        [Fact]
        public void A_5_Ed25519_Validation()
        {
            byte[] plaintext = Encoding.UTF8.GetBytes("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc");
            byte[] signature = Base64UrlEncoder.DecodeBytes("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");

            var signatureProvider = new EdDsaSignatureProvider(
                new EdDsaSecurityKey(EdDsa.CreateFromPublicKey(publicKey, ExtendedSecurityAlgorithms.Curves.Ed25519)),
                ExtendedSecurityAlgorithms.EdDsa);

            signatureProvider.Verify(plaintext, signature).Should().BeTrue();
        }
    }
}