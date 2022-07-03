using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens.Paseto;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    /// <summary>
    /// Test vectors from https://github.com/paseto-standard/test-vectors
    /// </summary>
    public class PasetoTestVectors
    {
        public static readonly TheoryData<PasetoTestVector> TestVectors = new TheoryData<PasetoTestVector>();
        
        static PasetoTestVectors()
        {
            var file = File.OpenRead("Tokens/Paseto/TestVectors/testvectors.json");
            var data = JsonNode.Parse(file);
            if (data == null) throw new Exception("Failed to load test vectors");

            foreach (var testVector in data["v1"]?.AsArray() ?? throw new Exception("Failed to load v1 test vectors"))
            {
                TestVectors.Add(new PasetoTestVector("v1", testVector));
            }
            foreach (var testVector in data["v2"]?.AsArray() ?? throw new Exception("Failed to load v2 test vectors"))
            {
                TestVectors.Add(new PasetoTestVector("v2", testVector));
            }
        }
        
        [Theory, MemberData(nameof(TestVectors))]
        public void ValidateToken_ExpectCorrectResult(PasetoTestVector testVector)
        {
            var handler = new PasetoTokenHandler();
            var result = handler.ValidateToken(testVector.Token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = testVector.Key
            });

            if (testVector.ShouldFail)
            {
                result.IsValid.Should().BeFalse(testVector.Name);
                result.Claims.Should().BeEmpty();
                result.ClaimsIdentity.Should().BeNull();
            }
            else
            {
                result.IsValid.Should().BeTrue(testVector.Name);
                result.Claims.Should().NotBeEmpty();
                result.ClaimsIdentity.Should().NotBeNull();

                foreach (var claim in testVector.ExpectedPayload.AsObject())
                {
                    result.Claims.Should().Contain(x => x.Key == claim.Key);

                    var value = result.Claims[claim.Key];
                    if (value is DateTime)
                    {
                        DateTime.TryParse(claim.Value.GetValue<string>(), DateTimeFormatInfo.InvariantInfo, DateTimeStyles.RoundtripKind, out var dateTime).Should().BeTrue();
                        value.Should().BeEquivalentTo(dateTime.ToUniversalTime());
                    }
                    else
                    {
                        value.Should().BeEquivalentTo(claim.Value.GetValue<string>());
                    }
                }
            }
        }
    }
    
    public class PasetoTestVector
    {
        public PasetoTestVector(string version, JsonNode data)
        {
            Name = data["name"]?.GetValue<string>();
            ShouldFail = data["expect-fail"]?.GetValue<bool>() ?? throw new Exception("Unable to parse expect-fail");
            Token = data["token"]?.GetValue<string>();
            
            var payload = data["payload"]?.GetValue<string>();
            if (payload != null)
            {
                ExpectedPayload = JsonNode.Parse(payload);
            }
            
            var publicKey = data["public-key"]?.GetValue<string>() ?? throw new Exception("Failed to find public key");
            if (version == "v1")
            {
                var rsaKey = RSA.Create();
                rsaKey.ImportFromPem(publicKey);
                Key = new RsaSecurityKey(rsaKey);
            }
            else if (version == "v2")
            {
                Key = new EdDsaSecurityKey(new Ed25519PublicKeyParameters(Base16.Decode(publicKey), 0));
            }
        }
            
        public string Name { get; }
        public bool ShouldFail { get; }
        public SecurityKey Key { get; }
        public string Token { get; }
        public JsonNode ExpectedPayload { get; }
    }
}