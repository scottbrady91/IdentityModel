using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Moq.Protected;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class JwtPayloadTokenHandlerTests
    {
        [Fact]
        public void CreateClaimsIdentity_WhenTokenIsNull_ExpectArgumentNullException()
        {
            var handler = new TestJwtPayloadTokenHandler();
            Assert.Throws<ArgumentNullException>(() => handler.TestCreateClaimsIdentity(null, new TokenValidationParameters()));
        }
        
        [Fact]
        public void CreateClaimsIdentity_WhenTokenValidationParametersAreNull_ExpectArgumentNullException()
        {
            var handler = new TestJwtPayloadTokenHandler();
            Assert.Throws<ArgumentNullException>(() => handler.TestCreateClaimsIdentity(new MockableJwtPayloadSecurityToken(), null));
        }

        [Fact]
        public void CreateClaimsIdentity_WhenTokenHasIssuer_ExpectClaimsToUseTokenIdentity()
        {
            const string expectedIssuer = "ids";
            var mockToken = new Mock<MockableJwtPayloadSecurityToken>();
            mockToken.Setup(x => x.Issuer).Returns(expectedIssuer);
            mockToken.Setup(x => x.Claims).Returns(new List<Claim> {new Claim("sub", "123")});
            
            var handler = new TestJwtPayloadTokenHandler();

            var identity = handler.TestCreateClaimsIdentity(mockToken.Object, new TokenValidationParameters());

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

            var identity = handler.TestCreateClaimsIdentity(mockToken.Object, new TokenValidationParameters());

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

            var identity = handler.TestCreateClaimsIdentity(mockToken.Object, new TokenValidationParameters());

            var mappedClaim = identity.Claims.Single(x => x.Type == claimWithProperty.Type && x.Value == claimWithProperty.Value);
            mappedClaim.Properties.Should().Contain(expectedProperty);
        }

        [Fact]
        public void ValidateTokenPayload_WhenTokenIsNull_ExpectResultWithArgumentNullException()
        {
            var result = new TestJwtPayloadTokenHandler().TestValidateTokenPayload(null, new TokenValidationParameters());

            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<ArgumentNullException>();
        }

        [Fact]
        public void ValidateTokenPayload_WhenTokenValidationParametersAreNull_ExpectResultWithArgumentNullException()
        {
            var token = CreateMockToken().Object;
            
            var result = new TestJwtPayloadTokenHandler().TestValidateTokenPayload(token, null);
            
            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<ArgumentNullException>();
        }

        [Fact]
        public void ValidateTokenPayload_WhenInvalidLifetime_ExpectFailureResultWithCorrectException()
        {
            var expectedException = new InvalidOperationException("correct error");
            
            var token = CreateMockToken().Object;
            var mockHandler = CreateMockHandler();
            mockHandler.Protected()
                .Setup("ValidateLifetime",
                    ItExpr.IsAny<DateTime?>(),
                    ItExpr.IsAny<DateTime?>(),
                    ItExpr.IsAny<SecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Throws(expectedException);
            
            var result = mockHandler.Object.TestValidateTokenPayload(token, new TokenValidationParameters());

            result.IsValid.Should().BeFalse();
            result.Exception.Should().Be(expectedException);
        }

        [Fact]
        public void ValidateTokenPayload_WhenInvalidAudience_ExpectFailureResultWithCorrectException()
        {
            var expectedException = new InvalidOperationException("correct error");
            
            var token = CreateMockToken().Object;
            var mockHandler = CreateMockHandler();
            mockHandler.Protected()
                .Setup("ValidateAudience",
                    ItExpr.IsAny<IEnumerable<string>>(),
                    ItExpr.IsAny<SecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Throws(expectedException);
            
            var result = mockHandler.Object.TestValidateTokenPayload(token, new TokenValidationParameters());

            result.IsValid.Should().BeFalse();
            result.Exception.Should().Be(expectedException);
        }

        [Fact]
        public void ValidateTokenPayload_WhenInvalidIssuer_ExpectFailureResultWithCorrectException()
        {
            var expectedException = new InvalidOperationException("correct error");
            
            var token = CreateMockToken().Object;
            var mockHandler = CreateMockHandler();
            mockHandler.Protected()
                .Setup("ValidateIssuer",
                    ItExpr.IsAny<string>(),
                    ItExpr.IsAny<SecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Throws(expectedException);
            
            var result = mockHandler.Object.TestValidateTokenPayload(token, new TokenValidationParameters());

            result.IsValid.Should().BeFalse();
            result.Exception.Should().Be(expectedException);
        }

        [Fact]
        public void ValidateTokenPayload_WhenTokenReplay_ExpectFailureResultWithCorrectException()
        {
            var expectedException = new InvalidOperationException("correct error");
            
            var token = CreateMockToken().Object;
            var mockHandler = CreateMockHandler();
            mockHandler.Protected()
                .Setup("ValidateTokenReplay",
                    ItExpr.IsAny<DateTime?>(),
                    ItExpr.IsAny<string>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Throws(expectedException);
            
            var result = mockHandler.Object.TestValidateTokenPayload(token, new TokenValidationParameters());

            result.IsValid.Should().BeFalse();
            result.Exception.Should().Be(expectedException);
        }

        [Fact]
        public void ValidateTokenPayload_WhenValidToken_ExpectSuccessResult()
        {
            var expectedIdentity = new ClaimsIdentity("test");
            
            var token = CreateMockToken().Object;
            var mockHandler = CreateMockHandler();
            mockHandler.Protected()
                .Setup<ClaimsIdentity>("CreateClaimsIdentity",
                    ItExpr.IsAny<JwtPayloadSecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Returns(expectedIdentity);
            
            var result = mockHandler.Object.TestValidateTokenPayload(token, new TokenValidationParameters());

            result.IsValid.Should().BeTrue();
            result.ClaimsIdentity.Should().Be(expectedIdentity);
            result.SecurityToken.Should().Be(token);
        }

        [Fact]
        public void GetDecryptionKeys_WhenKeyResolverReturnsKey_ExpectKeyFromResolver()
        {
            var expectedKey = new RsaSecurityKey(RSA.Create());
            
            var handler = new TestJwtPayloadTokenHandler();
            var keys = handler.TestGetDecryptionKeys("test", new TokenValidationParameters
            {
                TokenDecryptionKeyResolver = (token, securityToken, kid, parameters) => new[] {expectedKey},
                TokenDecryptionKey = new RsaSecurityKey(RSA.Create())
            }).ToList();

            keys.Count.Should().Be(1);
            keys.Should().Contain(expectedKey);
        }

        [Fact]
        public void GetDecryptionKeys_WheKeysInParameters_ExpectAllKeys()
        {
            var expectedKey1 = new RsaSecurityKey(RSA.Create());
            var expectedKey2 = new RsaSecurityKey(RSA.Create());
            
            var handler = new TestJwtPayloadTokenHandler();
            var keys = handler.TestGetDecryptionKeys("test", new TokenValidationParameters
            {
                TokenDecryptionKeyResolver = (token, securityToken, kid, parameters) => new List<SecurityKey>(),
                TokenDecryptionKey = expectedKey1,
                TokenDecryptionKeys = new[] {expectedKey2}
            }).ToList();

            keys.Count.Should().Be(2);
            keys.Should().Contain(expectedKey1);
            keys.Should().Contain(expectedKey2);
        }

        [Fact]
        public void GetSigningKeys_WhenKeyResolverReturnsKey_ExpectKeyFromResolver()
        {
            var expectedKey = new RsaSecurityKey(RSA.Create());
            
            var handler = new TestJwtPayloadTokenHandler();
            var keys = handler.TestGetSigningKeys("test", new TokenValidationParameters
            {
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) => new[] {expectedKey},
                IssuerSigningKey = new RsaSecurityKey(RSA.Create())
            }).ToList();

            keys.Count.Should().Be(1);
            keys.Should().Contain(expectedKey);
        }

        [Fact]
        public void GetSigningKeys_WheKeysInParameters_ExpectAllKeys()
        {
            var expectedKey1 = new RsaSecurityKey(RSA.Create());
            var expectedKey2 = new RsaSecurityKey(RSA.Create());
            
            var handler = new TestJwtPayloadTokenHandler();
            var keys = handler.TestGetSigningKeys("test", new TokenValidationParameters
            {
                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) => new List<SecurityKey>(),
                IssuerSigningKey = expectedKey1,
                IssuerSigningKeys = new[] {expectedKey2}
            }).ToList();

            keys.Count.Should().Be(2);
            keys.Should().Contain(expectedKey1);
            keys.Should().Contain(expectedKey2);
        }

        [Fact]
        public void ValidateToken_ISecurityTokenValidator_WhenSuccess_ExpectInnerTokenAndIdentity()
        {
            var token = Guid.NewGuid().ToString();
            var validationParameters = new TokenValidationParameters {ValidIssuer = Guid.NewGuid().ToString()};

            var expectedIdentity = new ClaimsIdentity(new List<Claim> {new Claim("sub", "123")}, "test");
            var expectedSecurityToken = new MockableJwtPayloadSecurityToken();

            var mockHandler = new Mock<TestJwtPayloadTokenHandler> {CallBase = true};
            mockHandler.Setup(x => x.ValidateToken(token, validationParameters))
                .Returns(new TokenValidationResult
                {
                    IsValid = true,
                    ClaimsIdentity = expectedIdentity,
                    SecurityToken = expectedSecurityToken
                });

            var claimsPrincipal = mockHandler.Object.ValidateToken(token, validationParameters, out var parsedToken);

            claimsPrincipal.Identity.Should().Be(expectedIdentity);
            parsedToken.Should().Be(expectedSecurityToken);
        }

        [Fact]
        public void ValidateToken_ISecurityTokenValidator_WhenFailure_ExpectInnerException()
        {
            var token = Guid.NewGuid().ToString();
            var validationParameters = new TokenValidationParameters();

            var expectedException = new InvalidOperationException("test");

            var mockHandler = new Mock<TestJwtPayloadTokenHandler> {CallBase = true};
            mockHandler.Setup(x => x.ValidateToken(token, validationParameters))
                .Returns(new TokenValidationResult
                {
                    IsValid = false,
                    Exception = expectedException
                });

            SecurityToken parsedToken = null;
            var exception = Assert.Throws(
                expectedException.GetType(),
                () => mockHandler.Object.ValidateToken(token, validationParameters, out parsedToken));
            
            parsedToken.Should().BeNull();
            exception.Should().Be(expectedException);
        }

        private static Mock<MockableJwtPayloadSecurityToken> CreateMockToken()
        {
            var mockToken = new Mock<MockableJwtPayloadSecurityToken>();
            
            mockToken.Setup(x => x.ValidTo).Returns(null);
            mockToken.Setup(x => x.ValidFrom).Returns(null);
            mockToken.Setup(x => x.Audiences).Returns(new []{"you"});
            mockToken.Setup(x => x.Issuer).Returns("me");
            mockToken.Setup(x => x.TokenHash).Returns("xyz");
            
            return mockToken;
        }

        private static Mock<TestJwtPayloadTokenHandler> CreateMockHandler()
        {
            var mockHandler = new Mock<TestJwtPayloadTokenHandler> {CallBase = false};
            mockHandler.Setup(x => x.TestValidateTokenPayload(It.IsAny<JwtPayloadSecurityToken>(), It.IsAny<TokenValidationParameters>()))
                .CallBase();
            mockHandler.Setup(x => x.TestCreateClaimsIdentity(It.IsAny<JwtPayloadSecurityToken>(), It.IsAny<TokenValidationParameters>()))
                .CallBase();
            
            return mockHandler;
        }
    }

    public class TestJwtPayloadTokenHandler : JwtPayloadTokenHandler
    {
        public virtual TokenValidationResult TestValidateTokenPayload(JwtPayloadSecurityToken token, TokenValidationParameters validationParameters)
            => base.ValidateTokenPayload(token, validationParameters);
        public virtual ClaimsIdentity TestCreateClaimsIdentity(JwtPayloadSecurityToken jwtToken, TokenValidationParameters validationParameters)
            => base.CreateClaimsIdentity(jwtToken, validationParameters);

        public virtual IEnumerable<SecurityKey> TestGetDecryptionKeys(string token, TokenValidationParameters validationParameters)
            => base.GetDecryptionKeys(token, validationParameters);

        public virtual IEnumerable<SecurityKey> TestGetSigningKeys(string token, TokenValidationParameters validationParameters)
            => base.GetSigningKeys(token, validationParameters);

        public override bool CanReadToken(string securityToken)
        {
            throw new NotImplementedException();
        }

        public override TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
        {
            throw new NotImplementedException();
        }
    }
    
    public class MockableJwtPayloadSecurityToken : JwtPayloadSecurityToken
    {
        public override SecurityKey SecurityKey => throw new NotImplementedException();
        public override SecurityKey SigningKey { get; set; }
    }
}