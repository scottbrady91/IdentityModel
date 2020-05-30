using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class EdDsaSecurityKeyTests
    {
        [Fact]
        public void ctor_WhenKeyParametersAreNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(() => new EdDsaSecurityKey((Ed25519PublicKeyParameters) null));
        
        [Fact]
        public void ctor_WhenEd25519PrivateKey_ExpectKeySetAndCorrectCurve()
        {
            var keyPair = GenerateEd25519KeyPair();

            var securityKey = new EdDsaSecurityKey((Ed25519PrivateKeyParameters) keyPair.Private);

            securityKey.CryptoProviderFactory.CustomCryptoProvider.Should().BeOfType<ExtendedCryptoProvider>();
            securityKey.KeyParameters.Should().Be(keyPair.Private);
            securityKey.Curve.Should().Be(ExtendedSecurityAlgorithms.Curves.Ed25519);
            securityKey.PrivateKeyStatus.Should().Be(PrivateKeyStatus.Exists);

#pragma warning disable 618
            securityKey.HasPrivateKey.Should().BeTrue();
#pragma warning restore 618
        }

        [Fact]
        public void ctor_WhenEd25519PublicKey_ExpectKeySetAndCorrectCurve()
        {
            var keyPair = GenerateEd25519KeyPair();

            var securityKey = new EdDsaSecurityKey((Ed25519PublicKeyParameters) keyPair.Public);

            securityKey.CryptoProviderFactory.CustomCryptoProvider.Should().BeOfType<ExtendedCryptoProvider>();
            securityKey.KeyParameters.Should().Be(keyPair.Public);
            securityKey.Curve.Should().Be(ExtendedSecurityAlgorithms.Curves.Ed25519);
            securityKey.PrivateKeyStatus.Should().Be(PrivateKeyStatus.DoesNotExist);

#pragma warning disable 618
            securityKey.HasPrivateKey.Should().BeFalse();
#pragma warning restore 618
        }
        
        private static AsymmetricCipherKeyPair GenerateEd25519KeyPair()
        {
            var keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            return keyPairGenerator.GenerateKeyPair();
        }
    }
}