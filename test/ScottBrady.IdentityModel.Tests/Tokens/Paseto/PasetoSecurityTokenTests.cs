using System;
using FluentAssertions;
using Newtonsoft.Json;
using ScottBrady.IdentityModel.Tokens.Paseto;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    public class PasetoSecurityTokenTests
    {
        [Fact]
        public void IssuedAt_WhenIatClaimHasIsoFormat_ExpectDateTime()
        {
            var expectedDateTime = new DateTime(2038, 03, 17, 01, 02, 03, DateTimeKind.Utc);
            
            var jwt = new
            {
                iss = "me",
                aud = "you",
                iat = "2038-03-17T01:02:03+00:00"
            };

            var innerToken = new TestPasetoToken();
            innerToken.SetPayload(JsonConvert.SerializeObject(jwt));
            var token = new PasetoSecurityToken(innerToken);

            token.IssuedAt.Should().BeCloseTo(expectedDateTime, TimeSpan.FromMilliseconds(10));
        }
        
        [Fact]
        public void ValidFrom_WhenIatClaimHasIsoFormat_ExpectDateTime()
        {
            var expectedDateTime = new DateTime(2028, 03, 17, 01, 02, 03, DateTimeKind.Utc);
            
            var jwt = new
            {
                iss = "me",
                aud = "you",
                nbf = "2028-03-17T01:02:03+00:00"
            };

            var innerToken = new TestPasetoToken();
            innerToken.SetPayload(JsonConvert.SerializeObject(jwt));
            var token = new PasetoSecurityToken(innerToken);

            token.ValidFrom.Should().BeCloseTo(expectedDateTime, TimeSpan.FromMilliseconds(10));
        }
        
        [Fact]
        public void ValidTo_WhenIatClaimHasIsoFormat_ExpectDateTime()
        {
            var expectedDateTime = new DateTime(2018, 03, 17, 01, 02, 03, DateTimeKind.Utc);
            
            var jwt = new
            {
                iss = "me",
                aud = "you",
                exp = "2018-03-17T01:02:03+00:00"
            };

            var innerToken = new TestPasetoToken();
            innerToken.SetPayload(JsonConvert.SerializeObject(jwt));
            var token = new PasetoSecurityToken(innerToken);

            token.ValidTo.Should().BeCloseTo(expectedDateTime, TimeSpan.FromMilliseconds(10));
        }
    }

    public class TestPasetoToken : PasetoToken
    {
        public new void SetPayload(string payload) => Payload = payload;
    }
}