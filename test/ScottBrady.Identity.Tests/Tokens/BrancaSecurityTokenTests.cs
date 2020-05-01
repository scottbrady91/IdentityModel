using System;
using FluentAssertions;
using Newtonsoft.Json;
using ScottBrady.Identity.Tokens;
using Xunit;

namespace ScottBrady.Identity.Tests.Tokens
{
    public class BrancaSecurityTokenTests
    {
        [Fact]
        public void ctor_WhenTokenPayloadIsNotJson_ExpectArgumentException()
            => Assert.Throws<ArgumentException>(() => new BrancaSecurityToken(new BrancaToken("<notjson></notjson>", 1588341410)));

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
                nbf = 1588341410,
                exp = 1588341499
            };

            var token = new BrancaSecurityToken(new BrancaToken(JsonConvert.SerializeObject(jwt), 1588341410));

            token.Id.Should().Be(jwt.jti);
            token.Issuer.Should().Be(jwt.iss);
            token.Audiences.Should().Contain(jwt.aud);
            token.Subject.Should().Be(jwt.sub);
            token.Actor.Should().Be(jwt.actort);
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
                nbf = 1588341410,
                exp = 1588341499
            };

            var token = new BrancaSecurityToken(new BrancaToken(JsonConvert.SerializeObject(jwt), 1588341410));

            token.Claims.Should().Contain(x => x.Type == "jti" && x.Value == "xyz");
            token.Claims.Should().Contain(x => x.Type == "iss" && x.Value == "me");
            token.Claims.Should().Contain(x => x.Type == "aud" && x.Value == "you");
            token.Claims.Should().Contain(x => x.Type == "sub" && x.Value == "123");
            token.Claims.Should().Contain(x => x.Type == "actort" && x.Value == "them");
            token.Claims.Should().Contain(x => x.Type == "nbf" && x.Value == "1588341410");
            token.Claims.Should().Contain(x => x.Type == "exp" && x.Value == "1588341499");
        }
    }
}