using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Tokens;
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

        private readonly List<SecurityKey> validSigningKeys = new List<SecurityKey>
        {
            new EdDsaSecurityKey(new Ed25519PublicKeyParameters(Convert.FromBase64String(ValidSigningPublicKey), 0))
        };
        
        private readonly PasetoVersion2 sut = new PasetoVersion2();
        
        [Fact]
        public void Verify_WhenTokenIsNull_ExpectArgumentNullException() 
            => Assert.Throws<ArgumentNullException>(() => sut.Verify(null, validSigningKeys));
        
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
            var token = new PasetoToken($"v3.{ValidPublicPurpose}.{ValidPublicPayload}");

            Assert.Throws<ArgumentException>(() => sut.Verify(token, validSigningKeys));
        }
        
        [Fact]
        public void Verify_WhenIncorrectPurpose_ExpectArgumentException()
        {
            var token = new PasetoToken($"{ValidVersion}.local.{ValidPublicPayload}");

            Assert.Throws<ArgumentException>(() => sut.Verify(token, validSigningKeys));
        }

        [Fact]
        public void Verify_WhenPayloadIsNotBase64UrlEncodedValue_ExpectFormatException()
        {
            var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.ey!!");

            Assert.Throws<FormatException>(() => sut.Verify(token, validSigningKeys));
        }

        [Fact]
        public void Verify_WhenPayloadDoesNotContainEnoughBytes_ExpectSecurityTokenInvalidSignatureException()
        {
            var payloadBytes = new byte[32];
            new Random().NextBytes(payloadBytes);
            
            var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.{Base64UrlEncoder.Encode(payloadBytes)}");
            
            Assert.Throws<SecurityTokenInvalidSignatureException>(() => sut.Verify(token, validSigningKeys));
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

            Assert.Throws<ArgumentException>(() => sut.Verify(token, validSigningKeys));
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

            Assert.Throws<SecurityTokenInvalidSignatureException>(() => sut.Verify(token, validSigningKeys));
        }

        [Fact]
        public void Verify_WhenSignatureIsValid_ExpectCorrectSecurityToken()
        {
            // "wxFZtnkkIXbcNh4WTYbTS8WgEyWaYRhfT1603kN6SdQ="
            // "v2.public.eyJzdWIiOiIxMjMiLCJleHAiOiIyMDIwLTA1LTAzVDEzOjE0OjE0LjE5MDA1OFoiff5U7ni0Bd5yame3wT41v26UMyH56JA4Un077FPn_UkGpx78fVgbegW0FEMLw0J61ms0OJHarRzyRrX4dWn6LgA"
            var token = new PasetoToken(validToken);

            var securityToken = sut.Verify(token, validSigningKeys);

            securityToken.Should().NotBeNull();
            securityToken.RawToken.Should().Be(token.RawToken);
        }
    }
}