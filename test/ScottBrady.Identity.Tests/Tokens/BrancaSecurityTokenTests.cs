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