using System;
using System.Linq;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using ScottBrady.Identity.Tokens;
using Xunit;

namespace ScottBrady.Identity.Tests.Tokens
{
    public class BrancaTokenHandlerTests
    {
        private const string ValidToken = "5K6Oid5pXkASEGvv63CHxpKhSX9passYQ4QhdSdCuOEnHlvBrvX414fWX6zUceAdg3DY9yTVQcmVZn0xr9lsBKBHDzOLNAGVlCs1SHlWIuFDfB8yGXO8EyNPnH9CBMueSEtNmISgcjM1ZmfmcD2EtE6";
        private const string ValidKey = "supersecretkeyyoushouldnotcommit";
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
            Assert.Throws<ArgumentNullException>(() => handler.CreateToken(payload, System.Text.Encoding.UTF8.GetBytes(ValidKey)));
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
            var key = System.Text.Encoding.UTF8.GetBytes(ValidKey);
            var handler = new BrancaTokenHandler();

            var token = handler.CreateToken(payload, key);

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
            var key = System.Text.Encoding.UTF8.GetBytes(ValidKey);
            var handler = new BrancaTokenHandler();
            
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(key), "chacha")
            });

            var parsedToken = handler.DecryptToken(token, key);
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
            Assert.Throws<ArgumentNullException>(() => handler.DecryptToken(token, System.Text.Encoding.UTF8.GetBytes(ValidKey)));
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
                new BrancaTokenHandler().DecryptToken(Base62.Encode(bytes), System.Text.Encoding.UTF8.GetBytes(ValidKey)));
        }
        
        [Fact]
        public void DecryptToken_WhenTokenHasIncorrectVersion_ExpectSecurityTokenException()
        {
            var bytes = new byte[120];
            new Random().NextBytes(bytes);
            bytes[0] = 0x00;

            Assert.Throws<SecurityTokenException>(() =>
                new BrancaTokenHandler().DecryptToken(Base62.Encode(bytes), System.Text.Encoding.UTF8.GetBytes(ValidKey)));
        }
        
        [Fact]
        public void DecryptToken_WhenValidToken_ExpectCorrectPayload()
        {
            var parsedToken = new BrancaTokenHandler().DecryptToken(ValidToken, System.Text.Encoding.UTF8.GetBytes(ValidKey));
            parsedToken.Payload.Should().Be(ExpectedPayload);
        }

        [Fact]
        public void EnryptAndDecryptToken_ExpectCorrectPayloadAndTimestamp()
        {
            var payload = Guid.NewGuid().ToString();
            var key = System.Text.Encoding.UTF8.GetBytes(ValidKey);
            var handler = new BrancaTokenHandler();

            var token = handler.CreateToken(payload, key);
            var decryptedPayload = handler.DecryptToken(token, key);

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
        public void ValidateToken_WhenTokenCannotBeRead_ExpectFailureWithInvalidOperationException()
        {
            var result = new BrancaTokenHandler().ValidateToken("=====", new TokenValidationParameters());
            
            result.Exception.Should().BeOfType<InvalidOperationException>();
        }

        /*[Fact]
        public void ValidateToken_WhenValidToken_TEST()
        {
            var result = new BrancaTokenHandler().ValidateToken(
                ValidToken,
                new TokenValidationParameters {TokenDecryptionKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(ValidKey))});
            
            
        }*/
    }
}