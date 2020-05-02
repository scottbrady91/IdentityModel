using System;
using System.Collections.Generic;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens
{
    public class JwtPayloadExtensionsTests
    {
        [Fact]
        public void ToJwtPayload_WhenTokenDescriptorIsNull_ExpectArgumentNullException()
        {
            SecurityTokenDescriptor descriptor = null;
            Assert.Throws<ArgumentNullException>(() => descriptor.ToJwtPayload());
        }
        
        [Fact]
        public void ToJwtPayload_WhenMultipleSubjectClaimsOfSameType_ExpectJsonArray()
        {
            const string claimType = "email";
            var claimValues = new[] {"bob@test", "alice@test"};
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Subject = new ClaimsIdentity(new List<Claim>
            {
                new Claim(claimType, claimValues[0]),
                new Claim(claimType, claimValues[1])
            }, "test");

            var jwtPayload = descriptor.ToJwtPayload();

            var claims = JObject.Parse(jwtPayload)[claimType];
            claims.Values<string>().Should().Contain(claimValues);
        }
        
        [Fact]
        public void ToJwtPayload_WhenMultipleClaimsOfSameType_ExpectJsonArray()
        {
            const string claimType = "email";
            var claimValues = new[] {"bob@test", "alice@test"};
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Claims = new Dictionary<string, object>
            {
                {claimType, claimValues}
            };

            var jwtPayload = descriptor.ToJwtPayload();

            var claims = JObject.Parse(jwtPayload)[claimType];
            claims.Values<string>().Should().Contain(claimValues);
        }

        [Fact]
        public void ToJwtPayload_WhenSubjectAndClaimsContainDuplicateTypes_ExpecSubjectClaimsReplaced()
        {
            var claimType = Guid.NewGuid().ToString();
            var expectedClaimValue = Guid.NewGuid().ToString();
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Subject = new ClaimsIdentity(new List<Claim> {new Claim(claimType, Guid.NewGuid().ToString())});
            descriptor.Claims = new Dictionary<string, object> {{claimType, expectedClaimValue}};

            var jwtPayload = descriptor.ToJwtPayload();
            
            var claims = JObject.Parse(jwtPayload)[claimType];
            claims.Value<string>().Should().Contain(expectedClaimValue);
        }

        [Fact]
        public void ToJwtPayload_WhenIssuerSet_ExpectIssuerClaim()
        {
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Issuer = "me";

            var jwtPayload = descriptor.ToJwtPayload();

            var issuer = JObject.Parse(jwtPayload)["iss"];
            issuer.Value<string>().Should().Be(descriptor.Issuer);
        }

        [Fact]
        public void ToJwtPayload_WhenIssuerSetInSubject_ExpectSubjectIssuerClaim()
        {
            var expectedIssuer = Guid.NewGuid().ToString();
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Subject = new ClaimsIdentity(new List<Claim> {new Claim("iss", expectedIssuer)});
            descriptor.Issuer = Guid.NewGuid().ToString();

            var jwtPayload = descriptor.ToJwtPayload();

            var issuer = JObject.Parse(jwtPayload)["iss"];
            issuer.Value<string>().Should().Be(expectedIssuer);
        }

        [Fact]
        public void ToJwtPayload_WhenIssuerSetInClaims_ExpectClaimsIssuerClaim()
        {
            var expectedIssuer = Guid.NewGuid().ToString();
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Claims = new Dictionary<string, object> {{"iss", expectedIssuer}};
            descriptor.Issuer = Guid.NewGuid().ToString();

            var jwtPayload = descriptor.ToJwtPayload();

            var issuer = JObject.Parse(jwtPayload)["iss"];
            issuer.Value<string>().Should().Be(expectedIssuer);
        }

        [Fact]
        public void ToJwtPayload_WhenAudienceSet_ExpectAudienceClaim()
        {
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Audience = "you";

            var jwtPayload = descriptor.ToJwtPayload();

            var audience = JObject.Parse(jwtPayload)["aud"];
            audience.Value<string>().Should().Be(descriptor.Audience);
        }

        [Fact]
        public void ToJwtPayload_WhenAudienceSetInSubject_ExpectSubjectAudienceClaim()
        {
            var expectedAudience = Guid.NewGuid().ToString();
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Subject = new ClaimsIdentity(new List<Claim> {new Claim("aud", expectedAudience)});
            descriptor.Audience = Guid.NewGuid().ToString();

            var jwtPayload = descriptor.ToJwtPayload();

            var audience = JObject.Parse(jwtPayload)["aud"];
            audience.Value<string>().Should().Be(expectedAudience);
        }

        [Fact]
        public void ToJwtPayload_WhenAudienceSetInClaims_ExpectClaimsAudienceClaim()
        {
            var expectedAudience = Guid.NewGuid().ToString();
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Claims = new Dictionary<string, object> {{"aud", expectedAudience}};
            descriptor.Audience = Guid.NewGuid().ToString();

            var jwtPayload = descriptor.ToJwtPayload();

            var audience = JObject.Parse(jwtPayload)["aud"];
            audience.Value<string>().Should().Be(expectedAudience);
        }

        [Fact]
        public void ToJwtPayload_WhenExpiryNotSet_ExpectExpirySetToOneHour()
        {
            var descriptor = new SecurityTokenDescriptor();

            var jwtPayload = descriptor.ToJwtPayload();

            var expiry = JObject.Parse(jwtPayload)["exp"];
            expiry.Value<long>().Should().BeCloseTo(
                (long) (EpochTime.GetIntDate(DateTime.UtcNow) + TimeSpan.FromMinutes(60).TotalSeconds), 
                10);
        }

        [Fact]
        public void ToJwtPayload_WhenExpirySet_ExpectExpiryClaim()
        {
            var expectedExpiry = DateTime.UtcNow.AddMinutes(5);
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Expires = expectedExpiry;

            var jwtPayload = descriptor.ToJwtPayload();

            var expiry = JObject.Parse(jwtPayload)["exp"];
            expiry.Value<long>().Should().Be(EpochTime.GetIntDate(expectedExpiry));
        }

        [Fact]
        public void ToJwtPayload_WhenExpirySetInClaims_ExpectClaimsExpiryClaim()
        {
            var expectedExpiry = EpochTime.GetIntDate(DateTime.UtcNow.AddMinutes(5));
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Claims = new Dictionary<string, object>{{"exp", expectedExpiry}};
            descriptor.Expires = DateTime.UtcNow.AddHours(42);

            var jwtPayload = descriptor.ToJwtPayload();

            var expiry = JObject.Parse(jwtPayload)["exp"];
            expiry.Value<long>().Should().Be(expectedExpiry);
        }

        [Fact]
        public void ToJwtPayload_WhenIssuedAtNotSet_ExpectIssuedAtSetToNow()
        {
            var descriptor = new SecurityTokenDescriptor();

            var jwtPayload = descriptor.ToJwtPayload();

            var issuedAt = JObject.Parse(jwtPayload)["iat"];
            issuedAt.Value<long>().Should().BeCloseTo(EpochTime.GetIntDate(DateTime.UtcNow), 10);
        }

        [Fact]
        public void ToJwtPayload_WhenIssuedAtSet_ExpectIssuedAtClaim()
        {
            var expectedIssuedAt = DateTime.UtcNow.AddMinutes(5);
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.IssuedAt = expectedIssuedAt;

            var jwtPayload = descriptor.ToJwtPayload();

            var issuedAt = JObject.Parse(jwtPayload)["iat"];
            issuedAt.Value<long>().Should().Be(EpochTime.GetIntDate(expectedIssuedAt));
        }

        [Fact]
        public void ToJwtPayload_WhenIssuedAtSetInClaims_ExpectClaimsIssuedAtClaim()
        {
            var expectedIssuedAt = EpochTime.GetIntDate(DateTime.UtcNow.AddMinutes(5));
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Claims = new Dictionary<string, object>{{"iat", expectedIssuedAt}};
            descriptor.IssuedAt = DateTime.UtcNow.AddHours(42);

            var jwtPayload = descriptor.ToJwtPayload();

            var issuedAt = JObject.Parse(jwtPayload)["iat"];
            issuedAt.Value<long>().Should().Be(expectedIssuedAt);
        }

        [Fact]
        public void ToJwtPayload_WhenNotBeforeNotSet_ExpectNotBeforeSetToNow()
        {
            var descriptor = new SecurityTokenDescriptor();

            var jwtPayload = descriptor.ToJwtPayload();

            var notBefore = JObject.Parse(jwtPayload)["nbf"];
            notBefore.Value<long>().Should().BeCloseTo(EpochTime.GetIntDate(DateTime.UtcNow), 10);
        }

        [Fact]
        public void ToJwtPayload_WhenNotBeforeSet_ExpectNotBeforeClaim()
        {
            var expectedNotBefore = DateTime.UtcNow.AddMinutes(5);
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.NotBefore = expectedNotBefore;

            var jwtPayload = descriptor.ToJwtPayload();

            var notBefore = JObject.Parse(jwtPayload)["nbf"];
            notBefore.Value<long>().Should().Be(EpochTime.GetIntDate(expectedNotBefore));
        }

        [Fact]
        public void ToJwtPayload_WhenNotBeforeSetInClaims_ExpectClaimsNotBeforeClaim()
        {
            var expectedNotBefore = EpochTime.GetIntDate(DateTime.UtcNow.AddMinutes(5));
            
            var descriptor = new SecurityTokenDescriptor();
            descriptor.Claims = new Dictionary<string, object>{{"nbf", expectedNotBefore}};
            descriptor.NotBefore = DateTime.UtcNow.AddHours(42);

            var jwtPayload = descriptor.ToJwtPayload();

            var notBefore = JObject.Parse(jwtPayload)["nbf"];
            notBefore.Value<long>().Should().Be(expectedNotBefore);
        }

        [Fact]
        public void ToJwtClaimDictionary_WhenClaimTypeHasSingleValue_ExpectSingleClaim()
        {
            var claim = new Claim("email", "bob@test");

            var dictionary = JwtPayloadExtensions.ToJwtClaimDictionary(new List<Claim> {claim});

            var values = dictionary[claim.Type];
            values.ToString().Should().Be(claim.Value);
        }

        [Fact]
        public void ToJwtClaimDictionary_WhenClaimTypeHasMultipleValues_ExpectEntryWithArrayValue()
        {
            const string claimType = "email";
            const string value1 = "bob@test";
            const string value2 = "alice@test";

            var dictionary = JwtPayloadExtensions.ToJwtClaimDictionary(new List<Claim>
            {
                new Claim(claimType, value1), new Claim(claimType, value2)
            });

            var entry = dictionary[claimType];
            var values = entry as IList<object>;

            values.Should().Contain(value1);
            values.Should().Contain(value2);
        }
    }
}