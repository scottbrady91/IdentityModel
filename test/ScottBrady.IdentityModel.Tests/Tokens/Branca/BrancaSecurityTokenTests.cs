using System;
using FluentAssertions;
using Newtonsoft.Json;
using ScottBrady.IdentityModel.Tokens.Branca;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Branca
{
    public class BrancaSecurityTokenTests
    {
        [Fact]
        public void ctor_ExpectBrancaTokenTimestampUsedForIssuedAt()
        {
            const uint expectedIssuedAt = 1588341499;

            var jwt = JsonConvert.SerializeObject(
                new
                {
                    iss = "me",
                    aud = "you",
                    iat = expectedIssuedAt - 1000
                });

            var token = new BrancaSecurityToken(new BrancaToken(System.Text.Encoding.UTF8.GetBytes(jwt), expectedIssuedAt));

            token.IssuedAt.Should().Be(DateTimeOffset.FromUnixTimeSeconds(expectedIssuedAt).UtcDateTime);
        }

        [Fact]
        public void ctor_WhenPayloadIsNotUtf8_ExpectException()
        {
            var payload = System.Text.Encoding.Unicode.GetBytes("������");
            var exception = Assert.Throws<ArgumentException>(() => new BrancaSecurityToken(new BrancaToken(payload, 0)));
            exception.Message.Should().Contain("Token does not contain valid JSON");
        }
    }
}