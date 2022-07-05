using System;
using System.Collections.Generic;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Moq.Protected;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens.Paseto;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    public class PasetoTokenHandlerTests
    {
        private const string TestVersion = "test";
        private readonly Mock<PasetoVersionStrategy> mockVersionStrategy = new Mock<PasetoVersionStrategy>();

        private readonly Mock<PasetoTokenHandler> mockedSut;
        private readonly PasetoTokenHandler sut;
        
        public PasetoTokenHandlerTests()
        {
            mockedSut = new Mock<PasetoTokenHandler>(
                new Dictionary<string, PasetoVersionStrategy>{{TestVersion, mockVersionStrategy.Object}})
            {
                CallBase = true
            };
            
            sut = mockedSut.Object;
        }
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void CanReadToken_WhenTokenIsNullOrWhitespace_ExpectFalse(string token)
        {
            var handler = new PasetoTokenHandler();
            var canReadToken = handler.CanReadToken(token);

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenTokenIsTooLong_ExpectFalse()
        {
            var tokenBytes = new byte[TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 1];
            new Random().NextBytes(tokenBytes);

            var canReadToken = sut.CanReadToken(Convert.ToBase64String(tokenBytes));

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenTokenHasTooManySegments_ExpectFalse()
        {
            const string invalidToken = "ey.ey.ey.ey.ey.ey";
            
            var canReadToken = sut.CanReadToken(invalidToken);

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenBrancaToken_ExpectFalse()
        {
            const string brancaToken = "5K6Oid5pXkASEGvv63CHxpKhSX9passYQ4QhdSdCuOEnHlvBrvX414fWX6zUceAdg3DY9yTVQcmVZn0xr9lsBKBHDzOLNAGVlCs1SHlWIuFDfB8yGXO8EyNPnH9CBMueSEtNmISgcjM1ZmfmcD2EtE6";
            
            var canReadToken = sut.CanReadToken(brancaToken);

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenPasetoToken_ExpectTrue()
        {
            var canReadToken = sut.CanReadToken(CreateTestToken());

            canReadToken.Should().BeTrue();
        }

        [Fact]
        public void CanValidateToken_ExpectTrue()
            => sut.CanValidateToken.Should().BeTrue();

        [Fact]
        public void CreateToken_WhenSecurityTokenDescriptorIsNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(() => sut.CreateToken(null));

        [Fact]
        public void CreateToken_WhenTokenVersionIsNotSupported_ExpectSecurityTokenException()
        {
            var tokenDescriptor = new PasetoSecurityTokenDescriptor("v42", PasetoConstants.Purposes.Public);

            Assert.Throws<SecurityTokenException>(() => sut.CreateToken(tokenDescriptor));
        }

        [Fact]
        public void CreateToken_WhenTokenPurposeNotSupported_ExpectSecurityTokenException()
        {
            var tokenDescriptor = new PasetoSecurityTokenDescriptor(TestVersion, "external");
            
            Assert.Throws<SecurityTokenException>(() => sut.CreateToken(tokenDescriptor));
        }

        [Fact]
        public void CreateToken_WhenLocalEncryptionThrowsException_ExpectSameException()
        {
            var expectedException = new ApplicationException("local");
            var tokenDescriptor = new PasetoSecurityTokenDescriptor(TestVersion, PasetoConstants.Purposes.Local);

            mockVersionStrategy.Setup(x => x.Encrypt(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<EncryptingCredentials>()))
                .Throws(expectedException);

            var exception = Assert.Throws(expectedException.GetType(), () => sut.CreateToken(tokenDescriptor));
            exception.Should().Be(expectedException);
        }

        [Fact]
        public void CreateToken_WhenPublicSigningThrowsException_ExpectSameException()
        {
            var expectedException = new ApplicationException("public");
            var tokenDescriptor = new PasetoSecurityTokenDescriptor(TestVersion, PasetoConstants.Purposes.Public);

            mockVersionStrategy.Setup(x => x.Sign(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<SigningCredentials>()))
                .Throws(expectedException);

            var exception = Assert.Throws(expectedException.GetType(), () => sut.CreateToken(tokenDescriptor));
            exception.Should().Be(expectedException);
        }

        [Fact]
        public void CreateToken_WhenLocalEncryptionSucceeds_ExpectLocalToken()
        {
            const string expectedToken = "local";
            var tokenDescriptor = new PasetoSecurityTokenDescriptor(TestVersion, PasetoConstants.Purposes.Local);

            mockVersionStrategy.Setup(x => x.Encrypt(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<EncryptingCredentials>()))
                .Returns(expectedToken);

            var token = sut.CreateToken(tokenDescriptor);

            token.Should().Be(expectedToken);
        }

        [Fact]
        public void CreateToken_WhenPublicSigningSucceeds_ExpectPublicToken()
        {
            const string expectedToken = "public";
            var tokenDescriptor = new PasetoSecurityTokenDescriptor(TestVersion, PasetoConstants.Purposes.Public);

            mockVersionStrategy.Setup(x => x.Sign(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<SigningCredentials>()))
                .Returns(expectedToken);

            var token = sut.CreateToken(tokenDescriptor);

            token.Should().Be(expectedToken);
        }
        
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void ValidateToken_WhenTokenIsNullOrWhitespace_ExpectFailureWithArgumentNullException(string token)
        {
            var result = sut.ValidateToken(token, new TokenValidationParameters());

            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<ArgumentNullException>();
        }

        [Fact]
        public void ValidateToken_WhenTokenValidationParametersAreNull_ExpectFailureWithArgumentNullException()
        {
            var result = sut.ValidateToken(CreateTestToken(), null);

            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<ArgumentNullException>();
        }

        [Fact]
        public void ValidateToken_WhenTokenCannotBeRead_ExpectFailureWithSecurityTokenException()
        {
            var result = sut.ValidateToken("ey.ey", new TokenValidationParameters());
            
            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<SecurityTokenException>();
        }

        [Fact]
        public void ValidateToken_WhenTokenVersionIsNotSupported_ExpectSecurityTokenException()
        {
            var result = sut.ValidateToken(CreateTestToken(version: "v42"), new TokenValidationParameters());
            
            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<SecurityTokenException>();
        }

        [Fact]
        public void ValidateToken_WhenTokenPurposeNotSupported_ExpectSecurityTokenException()
        {
            var result = sut.ValidateToken(CreateTestToken(purpose: "notapurpose"), new TokenValidationParameters());
            
            result.IsValid.Should().BeFalse();
            result.Exception.Should().BeOfType<SecurityTokenException>();
        }

        [Fact]
        public void ValidateToken_WhenLocalTokenValidationFails_ExpectFailureResultWithInnerException()
        {
            var expectedException = new ApplicationException("local");

            mockVersionStrategy.Setup(x => x.Decrypt(It.IsAny<PasetoToken>(), It.IsAny<IEnumerable<SecurityKey>>()))
                .Throws(expectedException);
            
            var result = sut.ValidateToken(CreateTestToken(purpose: PasetoConstants.Purposes.Local), new TokenValidationParameters());
            
            result.IsValid.Should().BeFalse();
            result.Exception.Should().Be(expectedException);
        }

        [Fact]
        public void ValidateToken_WhenPublicTokenValidationFails_ExpectFailureResultWithInnerException()
        {
            var expectedException = new ApplicationException("public");

            mockVersionStrategy.Setup(x => x.Verify(It.IsAny<PasetoToken>(), It.IsAny<IEnumerable<SecurityKey>>()))
                .Throws(expectedException);
            
            var result = sut.ValidateToken(CreateTestToken(purpose: PasetoConstants.Purposes.Public), new TokenValidationParameters());
            
            result.IsValid.Should().BeFalse();
            result.Exception.Should().Be(expectedException);
        }

        [Fact] 
        public void ValidateToken_WhenTokenPayloadValidationFails_ExpectPayloadValidationResult()
        {
            var expectedResult = new TokenValidationResult {IsValid = false, Exception = new ApplicationException("validation")};

            mockVersionStrategy.Setup(x => x.Verify(It.IsAny<PasetoToken>(), It.IsAny<IEnumerable<SecurityKey>>()))
                .Returns(new TestPasetoSecurityToken());
            mockedSut.Protected()
                .Setup<TokenValidationResult>("ValidateTokenPayload",
                    ItExpr.IsAny<JwtPayloadSecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Returns(expectedResult);
                
            var result = sut.ValidateToken(CreateTestToken(purpose: PasetoConstants.Purposes.Public), new TokenValidationParameters());
            
            result.Should().Be(expectedResult);
        }

        [Fact]
        public void ValidateToken_WhenValidLocalToken_ExpectSuccessResultWithSecurityTokenAndClaimsIdentity()
        {
            var expectedIdentity = new ClaimsIdentity("test");
            
            mockVersionStrategy.Setup(x => x.Decrypt(It.IsAny<PasetoToken>(), It.IsAny<IEnumerable<SecurityKey>>()))
                .Returns(new TestPasetoSecurityToken());
            mockedSut.Protected()
                .Setup<TokenValidationResult>("ValidateTokenPayload",
                    ItExpr.IsAny<JwtPayloadSecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Returns(new TokenValidationResult
                {
                    ClaimsIdentity = expectedIdentity,
                    IsValid = true
                });

            var result = sut.ValidateToken(CreateTestToken(purpose: PasetoConstants.Purposes.Local), new TokenValidationParameters());

            result.IsValid.Should().BeTrue();
            result.ClaimsIdentity.Should().Be(expectedIdentity);
            result.SecurityToken.Should().NotBeNull();
        }

        [Fact]
        public void ValidateToken_WhenValidPublicToken_ExpectSuccessResultWithSecurityTokenAndClaimsIdentity()
        {
            var expectedIdentity = new ClaimsIdentity("test");
            
            mockVersionStrategy.Setup(x => x.Verify(It.IsAny<PasetoToken>(), It.IsAny<IEnumerable<SecurityKey>>()))
                .Returns(new TestPasetoSecurityToken());
            mockedSut.Protected()
                .Setup<TokenValidationResult>("ValidateTokenPayload",
                    ItExpr.IsAny<JwtPayloadSecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Returns(new TokenValidationResult
                {
                    ClaimsIdentity = expectedIdentity,
                    IsValid = true
                });

            var result = sut.ValidateToken(CreateTestToken(purpose: PasetoConstants.Purposes.Public), new TokenValidationParameters());

            result.IsValid.Should().BeTrue();
            result.ClaimsIdentity.Should().Be(expectedIdentity);
            result.SecurityToken.Should().NotBeNull();
        }

        [Fact]
        public void ValidateToken_WhenSaveSignInTokenIsTrue_ExpectIdentityBootstrapContext()
        {
            var expectedToken = CreateTestToken(purpose: PasetoConstants.Purposes.Public);
            var expectedIdentity = new ClaimsIdentity("test");
            
            mockVersionStrategy.Setup(x => x.Verify(It.IsAny<PasetoToken>(), It.IsAny<IEnumerable<SecurityKey>>()))
                .Returns(new TestPasetoSecurityToken());
            mockedSut.Protected()
                .Setup<TokenValidationResult>("ValidateTokenPayload",
                    ItExpr.IsAny<JwtPayloadSecurityToken>(),
                    ItExpr.IsAny<TokenValidationParameters>())
                .Returns(new TokenValidationResult
                {
                    ClaimsIdentity = expectedIdentity,
                    IsValid = true
                });

            var result = sut.ValidateToken(expectedToken, new TokenValidationParameters {SaveSigninToken = true});

            result.IsValid.Should().BeTrue();
            result.ClaimsIdentity.BootstrapContext.Should().Be(expectedToken);
        }

        [Fact]
        public void CreateAndValidateToken_WhenV2PublicToken_ExpectCorrectClaims()
        {
            const string expectedClaimType = "name";
            const string expectedClaimValue = "scott";
            const string issuer = "me";
            const string audience = "you";

            var signingCredentials = new SigningCredentials(
                new EdDsaSecurityKey(EdDsa.Create(
                    new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519)
                    {
                        D = Convert.FromBase64String("TYXei5+8Qd2ZqKIlEuJJ3S50WYuocFTrqK+3/gHVH9B2hpLtAgscF2c9QuWCzV9fQxal3XBqTXivXJPpp79vgw==")
                    })), ExtendedSecurityAlgorithms.EdDsa);
            var verificationKeys =
                new EdDsaSecurityKey(EdDsa.Create(
                    new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519){X = Convert.FromBase64String("doaS7QILHBdnPULlgs1fX0MWpd1wak14r1yT6ae/b4M=")}));

            var handler = new PasetoTokenHandler();
            var token = handler.CreateToken(new PasetoSecurityTokenDescriptor(PasetoConstants.Versions.V2, PasetoConstants.Purposes.Public)
            {
                Issuer = issuer,
                Audience = audience,
                Claims = new Dictionary<string, object> {{expectedClaimType, expectedClaimValue}},
                SigningCredentials = signingCredentials
            });

            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = verificationKeys
            });

            result.IsValid.Should().BeTrue();
            result.ClaimsIdentity.HasClaim(expectedClaimType, expectedClaimValue).Should().BeTrue();
        }

        private static string CreateTestToken(string version = TestVersion, string purpose = "public", string payload = "ey")
            => $"{version}.{purpose}.{payload}";
    }
    
    internal class TestPasetoSecurityToken : PasetoSecurityToken { }
}