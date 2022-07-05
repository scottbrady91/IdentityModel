using System;
using System.Collections.Generic;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class JsonWebTokenHandlerTests
    {
        [Fact]
        public void WhenEdDsaTokenGenerated_ExpectEdDsaTokenVerifiable()
        {
            const string issuer = "me";
            const string audience = "you";
            const string subject = "123";
            
            var key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);

            var handler = new JsonWebTokenHandler();

            var jwt = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Expires = DateTime.UtcNow.AddMinutes(30),
                Claims = new Dictionary<string, object> {{"sub", subject}},
                SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(key), ExtendedSecurityAlgorithms.EdDsa)
            });

            var validationResult = handler.ValidateToken(jwt, new TokenValidationParameters
            {
                ValidIssuer = issuer,
                ValidAudience = audience,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                IssuerSigningKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(key.Parameters.Curve) {X = key.Parameters.X}))
            });

            validationResult.IsValid.Should().BeTrue();
            validationResult.ClaimsIdentity.Claims.Should().Contain(x => x.Type == "sub" && x.Value == subject);
        }
    }
}