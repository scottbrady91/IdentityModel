using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    public class PasetoTokenTests
    {
        private const string ValidToken = "v2.local.xyz";
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void ctor_WhenTokenIsNullOrWhitespace_ExpectArgumentNullException(string token)
            => Assert.Throws<ArgumentNullException>(() => new PasetoToken(token));

        [Fact]
        public void ctor_WhenTokenHasTooManyParts_ExpectArgumentException()
            => Assert.Throws<ArgumentException>(() => new PasetoToken("ey.ey.ey.ey.ey"));

        [Fact]
        public void ctor_WhenValidPasetoToken_ExpectCorrectProperties()
        {
            const string expectedVersion = "v2";
            const string expectedPurpose = "public";
            const string expectedPayload = "fa919c9d3d1248f29213521a40fc2b57";
            var token = $"{expectedVersion}.{expectedPurpose}.{expectedPayload}";

            var pasetoToken = new PasetoToken(token);

            pasetoToken.RawToken.Should().Be(token);
            pasetoToken.Version.Should().Be(expectedVersion);
            pasetoToken.Purpose.Should().Be(expectedPurpose);
            pasetoToken.EncodedPayload.Should().Be(expectedPayload);

            pasetoToken.Payload.Should().BeNull();
            pasetoToken.EncodedFooter.Should().BeNull();
        }
        
        [Fact]
        public void ctor_WhenValidPasetoTokenWithFooter_ExpectCorrectProperties()
        {
            const string expectedVersion = "v2";
            const string expectedPurpose = "public";
            const string expectedPayload = "fa919c9d3d1248f29213521a40fc2b57";
            const string expectedFooter = "{test}";
            var token = $"{expectedVersion}.{expectedPurpose}.{expectedPayload}.{Base64UrlEncoder.Encode(expectedFooter)}";

            var pasetoToken = new PasetoToken(token);

            pasetoToken.RawToken.Should().Be(token);
            pasetoToken.Version.Should().Be(expectedVersion);
            pasetoToken.Purpose.Should().Be(expectedPurpose);
            pasetoToken.EncodedPayload.Should().Be(expectedPayload);
            pasetoToken.EncodedFooter.Should().Be(Base64UrlEncoder.Encode(expectedFooter));
            pasetoToken.Footer.Should().Be(expectedFooter);

            pasetoToken.Payload.Should().BeNull();
        }
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void SetPayload_WhenPayloadIsNullOrWhitespace_ExpectArgumentNullException(string payload)
            => Assert.Throws<ArgumentNullException>(() => new PasetoToken(ValidToken).SetPayload(payload));

        [Fact]
        public void SetPayload_WhenPayloadIsNotJson_ExpectArgumentException()
        {
            const string invalidPayload = "<xml>oops</xml>";
            var token = new PasetoToken(ValidToken);

            Assert.Throws<ArgumentException>(() => token.SetPayload(invalidPayload));
        }
        
        [Fact]
        public void SetPayload_WhenValidPayload_ExpectParsedPayload()
        {
            const string expectedKey = "test";
            const string expectedValue = "test_val";
            
            var payload = $"{{ '{expectedKey}': '{expectedValue}' }}";
            var token = new PasetoToken(ValidToken);

            token.SetPayload(payload);

            token.Payload.Should().Be(payload);
        }
    }
}