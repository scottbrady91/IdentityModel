using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.WebEncoders.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens;

public class JwtBearerHandlerTests
{
    private readonly Mock<IOptionsMonitor<JwtBearerOptions>> mockOptionsMonitor;
    private readonly TestJwtBearerHandler sut;

    public JwtBearerHandlerTests()
    {
        mockOptionsMonitor = new Mock<IOptionsMonitor<JwtBearerOptions>>();
        sut = new TestJwtBearerHandler(mockOptionsMonitor.Object);
        
    }

    [Fact]
    public async Task HandleAuthenticateAsync_WhenValidEdDsaToken_ExpectSuccessResult()
    {
        const string issuer = "https://localhost";
        const string audience = "api1";
        var key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);
        
        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object> { { "sub", "123" } },
            SigningCredentials = new SigningCredentials(new EdDsaSecurityKey(key), ExtendedSecurityAlgorithms.EdDsa)
        });

        const string scheme = "test";
        var options = new JwtBearerOptions
        {
            TokenValidationParameters =
            {
                IssuerSigningKey = new EdDsaSecurityKey(key),
                ValidIssuer = issuer,
                ValidAudience = audience
            }
        };

        mockOptionsMonitor
            .Setup(x => x.Get(scheme))
            .Returns(options);
        
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer " + token;
        
        await sut.InitializeAsync(new AuthenticationScheme(scheme, scheme, typeof(TestJwtBearerHandler)), context);
        
        var authenticationResult = await sut.HandleAuthenticateAsync();

        authenticationResult.Succeeded.Should().BeTrue();
    }
}

#pragma warning disable CS0618 // Type or member is obsolete
public class TestJwtBearerHandler : JwtBearerHandler
{
    public TestJwtBearerHandler(IOptionsMonitor<JwtBearerOptions> options)
        : base(options, new NullLoggerFactory(), new UrlTestEncoder(), new SystemClock())
    {
    }
    
    public new Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return base.HandleAuthenticateAsync();
    }
}
#pragma warning restore CS0618 // Type or member is obsolete
