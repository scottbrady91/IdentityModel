using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens.Paseto;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    public class PasetoVersion2Tests
    {
        private const string ValidVersion = "v2";
        private const string ValidPublicPurpose = "public";
        private const string ValidPublicPayload = "eyJzdWIiOiIxMjMiLCJleHAiOiIyMDIwLTA1LTAyVDE2OjIzOjQwLjI1Njg1MTVaIn08nP0mX2YJvYOcMLBpiFbFs1C2gyNAJg_kpuniow671AfrEZWRDZWmLAQbuKRQNiJ2gIrXVeC-tO20zrVQ58wK";
        private readonly string validToken = $"{ValidVersion}.{ValidPublicPurpose}.{ValidPublicPayload}";
        
        private const string ValidSigningPrivateKey = "TYXei5+8Qd2ZqKIlEuJJ3S50WYuocFTrqK+3/gHVH9B2hpLtAgscF2c9QuWCzV9fQxal3XBqTXivXJPpp79vgw==";        
        private const string ValidSigningPublicKey = "doaS7QILHBdnPULlgs1fX0MWpd1wak14r1yT6ae/b4M=";

        private readonly SigningCredentials validSigningCredentials = new SigningCredentials(
            new EdDsaSecurityKey(new Ed25519PrivateKeyParameters(Convert.FromBase64String(ValidSigningPrivateKey), 0)), ExtendedSecurityAlgorithms.EdDsa);
        private readonly List<SecurityKey> validVerificationKeys = new List<SecurityKey>
        {
            new EdDsaSecurityKey(new Ed25519PublicKeyParameters(Convert.FromBase64String(ValidSigningPublicKey), 0))
        };
        
        private readonly PasetoVersion2 sut = new PasetoVersion2();

        [Fact]
        public void Sign_WhenPayloadIsNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(() => sut.Sign(null, null, validSigningCredentials));

        [Fact]
        public void Sign_WhenSigningCredentialsAreNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(() => sut.Sign("test", null, null));

        [Fact]
        public void Sign_WhenSigningCredentialsDoNotContainEdDsaSecurityKey_ExpectSecurityTokenInvalidSigningKeyException()
        {
            var signingCredentials = new SigningCredentials(new RsaSecurityKey(RSA.Create()), ExtendedSecurityAlgorithms.EdDsa);

            Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Sign("payload", null, signingCredentials));
        }

        [Fact]
        public void Sign_WhenSigningCredentialsNotConfigureForEdDSA_ExpectSecurityTokenInvalidSigningKeyException()
        {
            var signingCredentials = new SigningCredentials(validSigningCredentials.Key, ExtendedSecurityAlgorithms.XChaCha20Poly1305);

            Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Sign("payload", null, signingCredentials));
        }

        [Fact]
        public void Sign_WhenSigningCredentialsDoNotContainPrivateKey_ExpectSecurityTokenInvalidSigningKeyException()
        {
            var signingCredentials = new SigningCredentials(validVerificationKeys.First(), ExtendedSecurityAlgorithms.EdDsa);

            Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Sign("payload", null, signingCredentials));   
        }

        [Fact]
        public void Sign_WhenTokenGenerated_ExpectThreeParts()
        {
            var token = sut.Sign("payload", null, validSigningCredentials);

            token.Split('.').Length.Should().Be(3);
        }

        [Fact]
        public void Sign_WhenTokenGeneratedWithFooter_ExpectFourParts()
        {
            var token = sut.Sign("payload", "footer", validSigningCredentials);

            token.Split('.').Length.Should().Be(4);
        }
        
        [Fact]
        public void Verify_WhenTokenIsNull_ExpectArgumentNullException() 
            => Assert.Throws<ArgumentNullException>(() => sut.Verify(null, validVerificationKeys));
        
        [Fact]
        public void Verify_WhenSecurityKeysAreNull_ExpectArgumentNullException() 
            => Assert.Throws<ArgumentNullException>(() => sut.Verify(new PasetoToken(validToken), null));
        
        [Fact]
        public void Verify_WhenSecurityKeysAreEmpty_ExpectArgumentNullException() 
            => Assert.Throws<ArgumentNullException>(() => sut.Verify(new PasetoToken(validToken), new List<SecurityKey>()));

        [Fact]
        public void Verify_WhenNoEdDsaSecurityKeysPresent_ExpectSecurityTokenInvalidSigningKeyException()
        {
            var keys = new List<SecurityKey> {new RsaSecurityKey(RSA.Create())};

            Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Verify(new PasetoToken(validToken), keys));
        }
        
        [Fact]
        public void Verify_WhenIncorrectVersion_ExpectArgumentException()
        {
            var token = new PasetoToken($"v42.{ValidPublicPurpose}.{ValidPublicPayload}");

            Assert.Throws<ArgumentException>(() => sut.Verify(token, validVerificationKeys));
        }
        
        [Fact]
        public void Verify_WhenIncorrectPurpose_ExpectArgumentException()
        {
            var token = new PasetoToken($"{ValidVersion}.local.{ValidPublicPayload}");

            Assert.Throws<ArgumentException>(() => sut.Verify(token, validVerificationKeys));
        }

        [Fact]
        public void Verify_WhenPayloadIsNotBase64UrlEncodedValue_ExpectFormatException()
        {
            var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.ey!!");

            Assert.Throws<FormatException>(() => sut.Verify(token, validVerificationKeys));
        }

        [Fact]
        public void Verify_WhenPayloadDoesNotContainEnoughBytes_ExpectSecurityTokenInvalidSignatureException()
        {
            var payloadBytes = new byte[32];
            new Random().NextBytes(payloadBytes);
            
            var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.{Base64UrlEncoder.Encode(payloadBytes)}");
            
            Assert.Throws<SecurityTokenInvalidSignatureException>(() => sut.Verify(token, validVerificationKeys));
        }

        [Fact]
        public void Verify_WhenPayloadDoesNotContainJson_ExpectSecurityTokenException()
        {
            var payloadValue = "<xml>test</xml>";
            var payloadValueBytes = System.Text.Encoding.UTF8.GetBytes(payloadValue);
            
            var signature = new byte[64];
            new Random().NextBytes(signature);

            var payload = new byte[payloadValueBytes.Length + signature.Length];
            Buffer.BlockCopy(payloadValueBytes, 0, payload, 0, payloadValueBytes.Length);
            Buffer.BlockCopy(signature, 0, payload, payloadValueBytes.Length, signature.Length);

            var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.{Base64UrlEncoder.Encode(payload)}");

            Assert.Throws<ArgumentException>(() => sut.Verify(token, validVerificationKeys));
        }

        [Fact]
        public void Verify_WhenSignatureInvalid_ExpectSecurityTokenInvalidSignatureException()
        {
            var payloadValue = "{ 'test': 'test' }";
            var payloadValueBytes = System.Text.Encoding.UTF8.GetBytes(payloadValue);
            
            var signature = new byte[64];
            new Random().NextBytes(signature);

            var payload = new byte[payloadValueBytes.Length + signature.Length];
            Buffer.BlockCopy(payloadValueBytes, 0, payload, 0, payloadValueBytes.Length);
            Buffer.BlockCopy(signature, 0, payload, payloadValueBytes.Length, signature.Length);

            var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.{Base64UrlEncoder.Encode(payload)}");

            Assert.Throws<SecurityTokenInvalidSignatureException>(() => sut.Verify(token, validVerificationKeys));
        }

        [Fact]
        public void Verify_WhenSignatureIsValid_ExpectCorrectSecurityToken()
        {
            // "wxFZtnkkIXbcNh4WTYbTS8WgEyWaYRhfT1603kN6SdQ="
            // "v2.public.eyJzdWIiOiIxMjMiLCJleHAiOiIyMDIwLTA1LTAzVDEzOjE0OjE0LjE5MDA1OFoiff5U7ni0Bd5yame3wT41v26UMyH56JA4Un077FPn_UkGpx78fVgbegW0FEMLw0J61ms0OJHarRzyRrX4dWn6LgA"
            var token = new PasetoToken(validToken);

            var securityToken = sut.Verify(token, validVerificationKeys);

            securityToken.Should().NotBeNull();
            securityToken.RawToken.Should().Be(token.RawToken);
        }

        [Fact]
        public void Verify_WhenFooterPresentAndSignatureIsValid_ExpectCorrectSecurityToken()
        {
            var tokenWithFooter = new PasetoToken(
                "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");
            var publicKey = Convert.FromBase64String("Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=");

            var securityToken = sut.Verify(tokenWithFooter, new[] {new EdDsaSecurityKey(new Ed25519PublicKeyParameters(publicKey, 0))});

            securityToken.Should().NotBeNull();
            securityToken.RawToken.Should().Be(tokenWithFooter.RawToken);
        }

        [Fact]
        public void SignAndVerify_WhenKeysAreValid_ExpectCorrectClaimsFromPayload()
        {
            const string expectedClaimType = "test";
            const string expectedClaimValue = "test_val";
            var expectedPayload = $"{{ '{expectedClaimType}': '{expectedClaimValue}' }}";

            var token = sut.Sign(expectedPayload, null, validSigningCredentials);
            var parsedToken = sut.Verify(new PasetoToken(token), validVerificationKeys);

            parsedToken.Claims.Should().Contain(x => x.Type == expectedClaimType && x.Value == expectedClaimValue);
            parsedToken.RawToken.Should().Be(token);
        }

        [Fact]
        public void SignAndVerify_WhenKeysAreValidAndWithFooter_ExpectCorrectClaimsFromPayloadAndCorrectFooter()
        {
            const string expectedClaimType = "test";
            const string expectedClaimValue = "test_val";
            const string expectedFooter = "{'kid': '123'}";
            var expectedPayload = $"{{ '{expectedClaimType}': '{expectedClaimValue}' }}";

            var token = sut.Sign(expectedPayload, expectedFooter, validSigningCredentials);
            var parsedToken = sut.Verify(new PasetoToken(token), validVerificationKeys);

            parsedToken.Claims.Should().Contain(x => x.Type == expectedClaimType && x.Value == expectedClaimValue);
            parsedToken.RawToken.Should().Be(token);
            parsedToken.Footer.Should().Be(expectedFooter);
        }
    }
}