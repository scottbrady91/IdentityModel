using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens;

public class JsonWebTokenHandlerTests
{
    private const string Issuer = "me";
    private const string Audience = "you";
    private const string Subject = "123";

    private readonly SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
    {
        Issuer = Issuer,
        Audience = Audience,
        Expires = DateTime.UtcNow.AddMinutes(30),
        Claims = new Dictionary<string, object> {{"sub", Subject}}
    };

    private readonly TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = Issuer,
        ValidAudience = Audience,
        ValidateLifetime = true,
        RequireExpirationTime = true
    };
        
    [Fact]
    public async Task WhenEd25519TokenGenerated_ExpectEdDsaTokenVerifiable()
    {
            var key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);

            var handler = new JsonWebTokenHandler();
            securityTokenDescriptor.SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(key), ExtendedSecurityAlgorithms.EdDsa);
            tokenValidationParameters.IssuerSigningKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(key.Parameters.Curve) {X = key.Parameters.X}));

            var jwt = handler.CreateToken(securityTokenDescriptor);

            var validationResult = await handler.ValidateTokenAsync(jwt, tokenValidationParameters);

            validationResult.IsValid.Should().BeTrue();
            validationResult.ClaimsIdentity.Claims.Should().Contain(x => x.Type == "sub" && x.Value == Subject);
        }
        
    [Fact]
    public async Task WhenEd448TokenGenerated_ExpectEdDsaTokenVerifiable()
    {
            var key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed448);

            var handler = new JsonWebTokenHandler();
            securityTokenDescriptor.SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(key), ExtendedSecurityAlgorithms.EdDsa);
            tokenValidationParameters.IssuerSigningKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(key.Parameters.Curve) {X = key.Parameters.X}));

            var jwt = handler.CreateToken(securityTokenDescriptor);

            var validationResult = await handler.ValidateTokenAsync(jwt, tokenValidationParameters);

            validationResult.IsValid.Should().BeTrue();
            validationResult.ClaimsIdentity.Claims.Should().Contain(x => x.Type == "sub" && x.Value == Subject);
        }

    [Fact]
    public async Task WhenEd25519SignatureValidatedUsingEs448_ExpectInvalidToken()
    {
            var signingKey = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);
            var validationKey = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed448);

            var handler = new JsonWebTokenHandler();
            securityTokenDescriptor.SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(signingKey), ExtendedSecurityAlgorithms.EdDsa);
            tokenValidationParameters.IssuerSigningKey = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(validationKey.Parameters.Curve) {X = validationKey.Parameters.X}));
            
            var jwt = handler.CreateToken(securityTokenDescriptor);

            var validationResult = await handler.ValidateTokenAsync(jwt, tokenValidationParameters);

            validationResult.IsValid.Should().BeFalse();
        }
}