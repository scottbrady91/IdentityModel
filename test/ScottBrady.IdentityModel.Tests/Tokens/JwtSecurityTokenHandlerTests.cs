using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class JwtSecurityTokenHandlerTests
    {
        [Fact]
        public void WhenEdDsaTokenGenerated_ExpectEdDsaTokenVerifiable()
        {
            const string issuer = "me";
            const string audience = "you";
            const string subject = "123";
            
            var key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // ffs
            var handler = new JwtSecurityTokenHandler();

            var jwt = handler.CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Expires = DateTime.UtcNow.AddMinutes(30),
                Subject = new ClaimsIdentity(new[] {new Claim("sub", subject)}),
                SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(key), ExtendedSecurityAlgorithms.EdDsa)
            });

            var validationResult = handler.ValidateToken(jwt, new TokenValidationParameters
            {
                ValidIssuer = issuer,
                ValidAudience = audience,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                IssuerSigningKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(key.Parameters.Curve) {X = key.Parameters.X}))
            }, out _);
            
            validationResult.Claims.Should().Contain(x => x.Type == "sub" && x.Value == subject);
        }
    }
}