using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    public class PasetoTokenHandlerTests
    {
        private const string ValidToken = "v2.public.eyJzdWIiOiIxMjMiLCJleHAiOiIyMDIwLTA1LTAyVDE2OjIzOjQwLjI1Njg1MTVaIn08nP0mX2YJvYOcMLBpiFbFs1C2gyNAJg_kpuniow671AfrEZWRDZWmLAQbuKRQNiJ2gIrXVeC-tO20zrVQ58wK";
        private const string ValidPrivateKey = "TYXei5+8Qd2ZqKIlEuJJ3S50WYuocFTrqK+3/gHVH9B2hpLtAgscF2c9QuWCzV9fQxal3XBqTXivXJPpp79vgw==";
        private const string ValidPublicKey = "doaS7QILHBdnPULlgs1fX0MWpd1wak14r1yT6ae/b4M=";
        
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

            var canReadToken = new PasetoTokenHandler().CanReadToken(Convert.ToBase64String(tokenBytes));

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenTokenHasTooManySegments_ExpectFalse()
        {
            const string invalidToken = "ey.ey.ey.ey.ey.ey";
            
            var canReadToken = new PasetoTokenHandler().CanReadToken(invalidToken);

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenBrancaToken_ExpectFalse()
        {
            const string brancaToken = "5K6Oid5pXkASEGvv63CHxpKhSX9passYQ4QhdSdCuOEnHlvBrvX414fWX6zUceAdg3DY9yTVQcmVZn0xr9lsBKBHDzOLNAGVlCs1SHlWIuFDfB8yGXO8EyNPnH9CBMueSEtNmISgcjM1ZmfmcD2EtE6";
            
            var canReadToken = new PasetoTokenHandler().CanReadToken(brancaToken);

            canReadToken.Should().BeFalse();
        }

        [Fact]
        public void CanReadToken_WhenPasetoToken_ExpectTrue()
        {
            var canReadToken = new PasetoTokenHandler().CanReadToken(ValidToken);

            canReadToken.Should().BeTrue();
        }

        [Fact]
        public void CanValidateToken_ExpectTrue()
            => new PasetoTokenHandler().CanValidateToken.Should().BeTrue();
        
        
    }
}