using System;
using FluentAssertions;
using Newtonsoft.Json;
using ScottBrady.IdentityModel.Branca;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Branca
{
    public class BrancaSecurityTokenTests
    {
        [Fact]
        public void ctor_ExpectBrancaTokenTimestampUsedForIssuedAt()
        {
            const uint expectedIssuedAt = 1588341499;
            
            var jwt = new
            {
                iss = "me",
                aud = "you",
                iat = expectedIssuedAt - 1000
            };

            var token = new BrancaSecurityToken(new BrancaToken(JsonConvert.SerializeObject(jwt), expectedIssuedAt));

            token.IssuedAt.Should().Be(DateTimeOffset.FromUnixTimeSeconds(expectedIssuedAt).UtcDateTime);
        }
    }
}