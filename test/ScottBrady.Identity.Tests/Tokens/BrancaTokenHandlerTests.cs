using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using FluentAssertions;
using FluentAssertions.Extensions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Moq.Protected;
using Newtonsoft.Json.Linq;
using ScottBrady.Identity.Tokens;
using Xunit;

namespace ScottBrady.Identity.Tests.Tokens
{
    public class BrancaTokenHandlerTests
    {
        private const string ValidToken = "5K6Oid5pXkASEGvv63CHxpKhSX9passYQ4QhdSdCuOEnHlvBrvX414fWX6zUceAdg3DY9yTVQcmVZn0xr9lsBKBHDzOLNAGVlCs1SHlWIuFDfB8yGXO8EyNPnH9CBMueSEtNmISgcjM1ZmfmcD2EtE6";
        private readonly byte[] validKey = System.Text.Encoding.UTF8.GetBytes("supersecretkeyyoushouldnotcommit");
        private const string ExpectedPayload = "{\"user\":\"scott@scottbrady91.com\",\"scope\":[\"read\",\"write\",\"delete\"]}";

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void CanReadToken_WhenTokenIsNullOrWhitespace_ExpectFalse(string token)
        {
            var handler = new BrancaTokenHandler();
            var canReadToken = handler.CanReadToken(token);

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenTokenIsTooLong_ExpectFalse()
        {
            var tokenBytes = new byte[TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 1];
            new Random().NextBytes(tokenBytes);

            var canReadToken = new BrancaTokenHandler().CanReadToken(Convert.ToBase64String(tokenBytes));

            canReadToken.Should().BeFalse();
        }
        
        [Fact]
        public void CanReadToken_WhenJwtToken_ExpectFalse()
        {
            const string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiU2NvdHQgQnJhZHkiLCJpYXQiOjE1ODU3Njc0Mjl9.DcGCOpx19JQzVVeZPHgqB73rbLaCUsx-k6PuFdit6IM";
            
            var canReadToken = new BrancaTokenHandler().CanReadToken(jwt);

            canReadToken.Should().BeFalse();
        }
        
        [Fact]
        public void CanReadToken_WhenTokenContainsNonBase64Characters_ExpectFalse()
        {
            const string token = "token==";
            
            var canReadToken = new BrancaTokenHandler().CanReadToken(token);

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenBrancaToken_ExpectTrue()
        {
            var canReadToken = new BrancaTokenHandler().CanReadToken(ValidToken);

            canReadToken.Should().BeTrue();
        }
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void CreateToken_WhenPayloadIsNullOrWhitespace_ExpectArgumentNullException(string payload)
        {
            var handler = new BrancaTokenHandler();
            Assert.Throws<ArgumentNullException>(() => handler.CreateToken(payload, validKey));
        }
        
        [Fact]
        public void CreateToken_WhenKeyIsNull_ExpectInvalidOperationException() 
            => Assert.Throws<InvalidOperationException>(() => new BrancaTokenHandler().CreateToken("test", null));

        [Fact]
        public void CreateToken_WhenKeyIsNot32Bytes_ExpectInvalidOperationException()
            => Assert.Throws<InvalidOperationException>(() =>
                new BrancaTokenHandler().CreateToken("test", System.Text.Encoding.UTF8.GetBytes("iamonly14bytes")));

        [Fact]
        public void CreateToken_WhenTokenGenerated_ExpectBas62EncodedTokenWithCorrectLength()
        {
            var payload = Guid.NewGuid().ToString();
            var handler = new BrancaTokenHandler();

            var token = handler.CreateToken(payload, validKey);

            token.Any(x => !Base62.CharacterSet.Contains(x)).Should().BeFalse();
            Base62.Decode(token).Length.Should().Be(
                System.Text.Encoding.UTF8.GetBytes(payload).Length + 29 + 16);
        }

        [Fact]
        public void CreateToken_WhenSecurityTokenDescriptorIsNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(() => new BrancaTokenHandler().CreateToken(null));

        
        [Fact]
        public void CreateAndDecryptToken_WithSecurityTokenDescriptor_ExpectCorrectBrancaTimestampAndNoIatClaim()
        {
            var handler = new BrancaTokenHandler();
            
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(validKey), "chacha")
            });

            var parsedToken = handler.DecryptToken(token, validKey);
            var jObject = JObject.Parse(parsedToken.Payload);
            jObject["iat"].Should().BeNull();
            
            parsedToken.Timestamp.Should().BeCloseTo(DateTime.UtcNow, 1000);
        }
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void DecryptToken_WhenTokenIsNullOrWhitespace_ExpectArgumentNullException(string token)
        {
            var handler = new BrancaTokenHandler();
            Assert.Throws<ArgumentNullException>(() => handler.DecryptToken(token, validKey));
        }

        [Fact]
        public void DecryptToken_WhenKeyIsNull_ExpectInvalidOperationException() 
            => Assert.Throws<InvalidOperationException>(() => new BrancaTokenHandler().DecryptToken(ValidToken, null));

        [Fact]
        public void DecryptToken_WhenKeyIsNot32Bytes_ExpectInvalidOperationException()
            => Assert.Throws<InvalidOperationException>(() =>
                new BrancaTokenHandler().DecryptToken(ValidToken, System.Text.Encoding.UTF8.GetBytes("iamonly14bytes")));
        
        [Fact]
        public void DecryptToken_WhenTokenHasInvalidLength_ExpectSecurityTokenException()
        {
            var bytes = new byte[20];
            new Random().NextBytes(bytes);

            Assert.Throws<SecurityTokenException>(() =>
                new BrancaTokenHandler().DecryptToken(Base62.Encode(bytes), validKey));
        }
        
        [Fact]
        public void DecryptToken_WhenTokenHasIncorrectVersion_ExpectSecurityTokenException()
        {
            var bytes = new byte[120];
            new Random().NextBytes(bytes);
            bytes[0] = 0x00;

            Assert.Throws<SecurityTokenException>(() =>
                new BrancaTokenHandler().DecryptToken(Base62.Encode(bytes), validKey));
        }
        
        [Fact]
        public void DecryptToken_WhenValidToken_ExpectCorrectPayload()
        {
            var parsedToken = new BrancaTokenHandler().DecryptToken(ValidToken, validKey);
            parsedToken.Payload.Should().Be(ExpectedPayload);
        }

        [Fact]
        public void EnryptAndDecryptToken_ExpectCorrectPayloadAndTimestamp()
        {
            var payload = Guid.NewGuid().ToString();
            var handler = new BrancaTokenHandler();

            var token = handler.CreateToken(payload, validKey);
            var decryptedPayload = handler.DecryptToken(token, validKey);

            decryptedPayload.Payload.Should().Be(payload);
            decryptedPayload.Timestamp.Should().BeCloseTo(DateTime.UtcNow, 1000);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void ValidateToken_WhenTokenIsNullOrWhitespace_ExpectFailureWithArgumentNullException(string token)
        {
            var result = new BrancaTokenHandler().ValidateToken(token, new TokenValidationParameters());

            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<ArgumentNullException>();
        }

        [Fact]
        public void ValidateToken_WhenTokenValidationParametersAreNull_ExpectFailureWithArgumentNullException()
        {
            var result = new BrancaTokenHandler().ValidateToken(ValidToken, null);
            
            result.Exception.Should().BeOfType<ArgumentNullException>();
        }

        [Fact]
        public void ValidateToken_WhenTokenCannotBeRead_ExpectFailureWithSecurityTokenException()
        {
            var result = new BrancaTokenHandler().ValidateToken("=====", new TokenValidationParameters());
            
            result.Exception.Should().BeOfType<SecurityTokenException>();
        }

        [Fact]
        public void ValidateToken_WhenIncorrectDecryptionKey_ExpectFailureWithSecurityTokenDecryptionFailedException()
        {
            var key = new byte[32];
            new Random().NextBytes(key);

            var result = new BrancaTokenHandler().ValidateToken(
                ValidToken,
                new TokenValidationParameters {TokenDecryptionKey = new SymmetricSecurityKey(key)});

            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<SecurityTokenDecryptionFailedException>();
        }

        [Fact]
        public void ValidateToken_WhenTokenPayloadIsNotJson_ExpectFailureWithArgumentException()
        {
            const string tokenWithInvalidPayload = "9FvacDjvxjhWG5cqkP3WBrIb6cuCBl9sPjJvkrGX0XI8tbLJQe6Pb2EcbeyOGkbextBqDdHa66pF0HBMg";

            var result = new BrancaTokenHandler().ValidateToken(
                tokenWithInvalidPayload,
                new TokenValidationParameters {TokenDecryptionKey = new SymmetricSecurityKey(validKey)});

            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<ArgumentException>();
        }

        [Fact]
        public void ValidateToken_WhenValidToken_ExpectSuccessResultWithSecurityTokenAndClaimsIdentity()
        {
            var expectedIdentity = new ClaimsIdentity("test");
            
            var mockHandler = new Mock<BrancaTokenHandler> {CallBase = true};
            mockHandler.Protected()
                .Setup<TokenValidationResult>("ValidateTokenPayload",
                    ItExpr.IsAny<BrancaSecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Returns(new TokenValidationResult
                {
                    ClaimsIdentity = expectedIdentity,
                    IsValid = true
                });

            var result = mockHandler.Object.ValidateToken(
                ValidToken,
                new TokenValidationParameters {TokenDecryptionKey = new SymmetricSecurityKey(validKey)});

            result.IsValid.Should().BeTrue();
            result.ClaimsIdentity.Should().Be(expectedIdentity);
            result.SecurityToken.Should().NotBeNull();
        }
        
        [Fact]
        public void CreateAndValidateToken_WithSecurityTokenDescriptor_ExpectCorrectBrancaTimestampAndNoIatClaim()
        {
            const string issuer = "me";
            const string audience = "you";
            const string subject = "123";
            var expires = DateTime.UtcNow.AddDays(1);
            var notBefore = DateTime.UtcNow;
            
            var handler = new BrancaTokenHandler();

            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Expires = expires,
                NotBefore = notBefore,
                Claims = new Dictionary<string, object> {{"sub", subject}},
                EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(validKey), "chacha")
            });

            var validatedToken = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = issuer,
                ValidAudience = audience,
                TokenDecryptionKey = new SymmetricSecurityKey(validKey)
            });

            validatedToken.IsValid.Should().BeTrue();
            validatedToken.ClaimsIdentity.Claims.Should().Contain(
                x => x.Type == "sub" && x.Value == subject);

            var brancaToken = (BrancaSecurityToken) validatedToken.SecurityToken;
            brancaToken.Issuer.Should().Be(issuer);
            brancaToken.Audiences.Should().Contain(audience);
            brancaToken.Subject.Should().Be(subject);
            brancaToken.IssuedAt.Should().BeWithin(1.Minutes()).After(notBefore);
            brancaToken.ValidFrom.Should().BeWithin(0.Seconds()).After(notBefore);
            brancaToken.ValidTo.Should().BeWithin(0.Seconds()).After(expires);
        }

        [Fact]
        public void GetDecryptionKeys_WhenKeyResolverReturnsKey_ExpectKeyFromResolver()
        {
            var expectedKey = new byte[32];
            new Random().NextBytes(expectedKey);
            
            var handler = new TestBrancaTokenHandler();
            var keys = handler.GetDecryptionKeys("test", new TokenValidationParameters
            {
                TokenDecryptionKeyResolver =
                    (token, securityToken, kid, parameters) => new[] {new SymmetricSecurityKey(expectedKey)},
                TokenDecryptionKey = new SymmetricSecurityKey(validKey)
            }).ToList();

            keys.Count.Should().Be(1);
            keys.Should().Contain(x => x.Key.SequenceEqual(expectedKey));
        }

        [Fact]
        public void GetDecryptionKeys_WheKeysInParameters_ExpectAllKeys()
        {
            var expectedKey1 = new byte[32];
            var expectedKey2 = new byte[32];
            new Random().NextBytes(expectedKey1);
            new Random().NextBytes(expectedKey2);
            
            var handler = new TestBrancaTokenHandler();
            var keys = handler.GetDecryptionKeys("test", new TokenValidationParameters
            {
                TokenDecryptionKeyResolver = (token, securityToken, kid, parameters) => new List<SecurityKey>(),
                TokenDecryptionKey = new SymmetricSecurityKey(expectedKey1),
                TokenDecryptionKeys = new[] {new SymmetricSecurityKey(expectedKey2)}
            }).ToList();

            keys.Count.Should().Be(2);
            keys.Should().Contain(x => x.Key.SequenceEqual(expectedKey1));
            keys.Should().Contain(x => x.Key.SequenceEqual(expectedKey2));
        }

        [Fact]
        public void GetDecryptionKeys_WheInvalidKeysInParameters_ExpectInvalidKeysRemoved()
        {
            var expectedKey = new byte[32];
            new Random().NextBytes(expectedKey);
            
            var handler = new TestBrancaTokenHandler();
            var keys = handler.GetDecryptionKeys("test", new TokenValidationParameters
            {
                TokenDecryptionKeyResolver = (token, securityToken, kid, parameters) => new List<SecurityKey>(),
                TokenDecryptionKey = new SymmetricSecurityKey(expectedKey),
                TokenDecryptionKeys = new[] {new RsaSecurityKey(RSA.Create())}
            }).ToList();

            keys.Count.Should().Be(1);
            keys.Should().Contain(x => x.Key.SequenceEqual(expectedKey));
        }
    }

    public class TestBrancaTokenHandler : BrancaTokenHandler
    {
        public new IEnumerable<SymmetricSecurityKey> GetDecryptionKeys(string token, TokenValidationParameters validationParameters) 
            => base.GetDecryptionKeys(token, validationParameters);
    }
}