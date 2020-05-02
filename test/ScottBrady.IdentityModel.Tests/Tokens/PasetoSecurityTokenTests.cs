using System;
using FluentAssertions;
using Newtonsoft.Json;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class PasetoSecurityTokenTests
    {
        private const string ValidToken = "v2.public.eyJzdWIiOiIxMjMiLCJleHAiOiIyMDIwLTA1LTAyVDE2OjIzOjQwLjI1Njg1MTVaIn08nP0mX2YJvYOcMLBpiFbFs1C2gyNAJg_kpuniow671AfrEZWRDZWmLAQbuKRQNiJ2gIrXVeC-tO20zrVQ58wK";
        
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

            var token = new PasetoSecurityToken(JsonConvert.SerializeObject(jwt));

            token.IssuedAt.Should().BeCloseTo(expectedDateTime);
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

            var token = new PasetoSecurityToken(JsonConvert.SerializeObject(jwt));

            token.ValidFrom.Should().BeCloseTo(expectedDateTime);
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

            var token = new PasetoSecurityToken(JsonConvert.SerializeObject(jwt));

            token.ValidTo.Should().BeCloseTo(expectedDateTime);
        }
    }
}