using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
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
    }
}