using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class JwtPayloadSecurityTokenTests
    {
        [Fact]
        public void ctor_WhenTokenPayloadIsNotJson_ExpectArgumentException()
            => Assert.Throws<ArgumentException>(() => new TestJwtPayloadSecurityToken("<notjson></notjson>"));

        [Fact]
        public void ctor_WhenTokenContainsJson_ExpectJwtClaimsParsed()
        {
            var jwt = new
            {
                jti = "xyz",
                iss = "me",
                aud = "you",
                sub = "123",
                actort = "them", // 🤷‍
                iat = 1588341409,
                nbf = 1588341410,
                exp = 1588341499
            };

            var token = new TestJwtPayloadSecurityToken(JsonConvert.SerializeObject(jwt));

            token.Id.Should().Be(jwt.jti);
            token.Issuer.Should().Be(jwt.iss);
            token.Audiences.Should().Contain(jwt.aud);
            token.Subject.Should().Be(jwt.sub);
            token.Actor.Should().Be(jwt.actort);
            token.IssuedAt.Should().Be(DateTimeOffset.FromUnixTimeSeconds(jwt.iat).UtcDateTime);
            token.ValidFrom.Should().Be(DateTimeOffset.FromUnixTimeSeconds(jwt.nbf).UtcDateTime);
            token.ValidTo.Should().Be(DateTimeOffset.FromUnixTimeSeconds(jwt.exp).UtcDateTime);
        }
        
        [Fact]
        public void ctor_WhenTokenContainsJson_ExpectClaimsParsed()
        {
            var jwt = new
            {
                jti = "xyz",
                iss = "me",
                aud = "you",
                sub = "123",
                actort = "them",
                iat = 1588341409,
                nbf = 1588341410,
                exp = 1588341499
            };

            var token = new TestJwtPayloadSecurityToken(JsonConvert.SerializeObject(jwt));

            token.Claims.Should().Contain(x => x.Type == "jti" && x.Value == jwt.jti);
            token.Claims.Should().Contain(x => x.Type == "iss" && x.Value == jwt.iss);
            token.Claims.Should().Contain(x => x.Type == "aud" && x.Value == jwt.aud);
            token.Claims.Should().Contain(x => x.Type == "sub" && x.Value == jwt.sub);
            token.Claims.Should().Contain(x => x.Type == "actort" && x.Value == jwt.actort);
            token.Claims.Should().Contain(x => x.Type == "iat" && x.Value == jwt.iat.ToString());
            token.Claims.Should().Contain(x => x.Type == "nbf" && x.Value == jwt.nbf.ToString());
            token.Claims.Should().Contain(x => x.Type == "exp" && x.Value == jwt.exp.ToString());
        }
    }
    
    internal class TestJwtPayloadSecurityToken : JwtPayloadSecurityToken
    {
        public TestJwtPayloadSecurityToken(string payload) : base(payload)
        {
        }

        public override SecurityKey SecurityKey { get; }
        public override SecurityKey SigningKey { get; set; }
    }
}