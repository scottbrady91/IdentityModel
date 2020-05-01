using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using ScottBrady.Identity.Tokens;
using Xunit;

namespace ScottBrady.Identity.Tests.Tokens
{
    public class JwtPayloadTokenHandlerTests
    {
        [Fact]
        public void CreateClaimsIdentity_WhenTokenIsNull_ExpectArgumentNullException()
        {
            var handler = new TestJwtPayloadTokenHandler();
            Assert.Throws<ArgumentNullException>(() => handler.CreateClaimsIdentity(null, new TokenValidationParameters()));
        }
        
        [Fact]
        public void CreateClaimsIdentity_WhenTokenValidationParametersAreNull_ExpectArgumentNullException()
        {
            var handler = new TestJwtPayloadTokenHandler();
            Assert.Throws<ArgumentNullException>(() => handler.CreateClaimsIdentity(new MockableJwtPayloadSecurityToken(), null));
        }

        [Fact]
        public void CreateClaimsIdentity_WhenTokenHasIssuer_ExpectClaimsToUseTokenIdentity()
        {
            const string expectedIssuer = "ids";
            var mockToken = new Mock<MockableJwtPayloadSecurityToken>();
            mockToken.Setup(x => x.Issuer).Returns(expectedIssuer);
            mockToken.Setup(x => x.Claims).Returns(new List<Claim> {new Claim("sub", "123")});
            
            var handler = new TestJwtPayloadTokenHandler();

            var identity = handler.CreateClaimsIdentity(mockToken.Object, new TokenValidationParameters());

            identity.Claims.All(x => x.Issuer == expectedIssuer).Should().BeTrue();
            identity.Claims.All(x => x.OriginalIssuer == expectedIssuer).Should().BeTrue();
        }

        [Fact]
        public void CreateClaimsIdentity_WhenTokenHasNoIssuer_ExpectClaimsToUseDefaultIssuer()
        {
            var mockToken = new Mock<MockableJwtPayloadSecurityToken>();
            mockToken.Setup(x => x.Issuer).Returns((string) null);
            mockToken.Setup(x => x.Claims).Returns(new List<Claim> {new Claim("sub", "123")});

            var handler = new TestJwtPayloadTokenHandler();

            var identity = handler.CreateClaimsIdentity(mockToken.Object, new TokenValidationParameters());

            identity.Claims.All(x => x.Issuer == ClaimsIdentity.DefaultIssuer).Should().BeTrue();
            identity.Claims.All(x => x.OriginalIssuer == ClaimsIdentity.DefaultIssuer).Should().BeTrue();
        }

        [Fact]
        public void CreateClaimsIdentity_WhenTokenHasClaimsWithProperties_ExpectPropertiesPersisted()
        {
            var expectedProperty = new KeyValuePair<string, string>("test", "test_val");
            var claimWithProperty = new Claim("sub", "123") {Properties = {expectedProperty}};
            
            var mockToken = new Mock<MockableJwtPayloadSecurityToken>();
            mockToken.Setup(x => x.Issuer).Returns((string) null);
            mockToken.Setup(x => x.Claims).Returns(new List<Claim> {claimWithProperty});

            var handler = new TestJwtPayloadTokenHandler();

            var identity = handler.CreateClaimsIdentity(mockToken.Object, new TokenValidationParameters());

            var mappedClaim = identity.Claims.Single(x => x.Type == claimWithProperty.Type && x.Value == claimWithProperty.Value);
            mappedClaim.Properties.Should().Contain(expectedProperty);
        }

        [Fact]
        public void ValidateTokenPayload_WhenTokenIsNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(
                () => new TestJwtPayloadTokenHandler().ValidateTokenPayload(null, new TokenValidationParameters()));
        
        [Fact]
        public void ValidateTokenPayload_WhenTokenValidationParametersAreNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(
                () => new TestJwtPayloadTokenHandler().ValidateTokenPayload(new MockableJwtPayloadSecurityToken(), null));

        [Fact]
        public void ValidateTokenPayload_WhenTokenHasExpired()
        {
            var issued = DateTime.UtcNow.AddDays(-3);
            var expires = DateTime.UtcNow.AddDays(-2);

            var mockToken = new Mock<MockableJwtPayloadSecurityToken>();
            
            var handler = new TestJwtPayloadTokenHandler();

            var result = handler.ValidateTokenPayload(mockToken.Object, new TokenValidationParameters());

            result.IsValid.Should().BeTrue();
        }
    }

    internal class TestJwtPayloadTokenHandler : JwtPayloadTokenHandler
    {
        public new TokenValidationResult ValidateTokenPayload(JwtPayloadSecurityToken token, TokenValidationParameters validationParameters)
            => base.ValidateTokenPayload(token, validationParameters);
        public new ClaimsIdentity CreateClaimsIdentity(JwtPayloadSecurityToken jwtToken, TokenValidationParameters validationParameters)
            => base.CreateClaimsIdentity(jwtToken, validationParameters);
    }
    
    public class MockableJwtPayloadSecurityToken : JwtPayloadSecurityToken
    {
        public override SecurityKey SecurityKey => throw new NotImplementedException();
        public override SecurityKey SigningKey { get; set; }
    }
}