using System;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using FluentAssertions;
using ScottBrady.IdentityModel.Tokens.Branca;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Branca
{
    /// <summary>
    /// Test vectors from https://github.com/tuupola/branca-spec
    /// </summary>
    public class BrancaTestVectors
    {
        public static readonly TheoryData<BrancaTestVector> EncodingTestVectors = new TheoryData<BrancaTestVector>();
        public static readonly TheoryData<BrancaTestVector> DecodingTestVectors = new TheoryData<BrancaTestVector>();

        static BrancaTestVectors()
        {
            var file = File.OpenRead("Tokens/Branca/TestVectors/testvectors.json");
            var data = JsonNode.Parse(file);
            if (data == null) throw new Exception("Failed to load test vectors");

            var testGroups = data["testGroups"].AsArray();
            var encodingTestVectors = testGroups.FirstOrDefault(x => x["testType"]?.GetValue<string>() == "encoding");
            var decodingTestVectors = testGroups.FirstOrDefault(x => x["testType"]?.GetValue<string>() == "decoding");

            foreach (var testVector in encodingTestVectors?["tests"]?.AsArray() ?? throw new Exception("Failed to load encoding` test vectors"))
            {
                EncodingTestVectors.Add(new BrancaTestVector(testVector));
            }
            foreach (var testVector in decodingTestVectors?["tests"]?.AsArray() ?? throw new Exception("Failed to load decoding test vectors"))
            {
                DecodingTestVectors.Add(new BrancaTestVector(testVector));
            }
        }

        [Theory, MemberData(nameof(EncodingTestVectors))]
        public void CreateToken_ExpectCorrectResult(BrancaTestVector testVector)
        {
            var handler = new TestBrancaTokenHandler {Nonce = testVector.Nonce};
            var token = handler.CreateToken(testVector.Message, testVector.TimeStamp, testVector.Key);

            token.Should().Be(testVector.Token);
        }
        
        [Theory, MemberData(nameof(DecodingTestVectors))]
        public void ValidateToken_ExpectCorrectResult(BrancaTestVector testVector)
        {
            var handler = new BrancaTokenHandler();

            BrancaToken result = null;
            Exception exception = null;
            try
            {
                result = handler.DecryptToken(testVector.Token, testVector.Key);
            }
            catch (Exception e)
            {
                exception = e;
            }

            if (testVector.IsValid)
            {
                result.Should().NotBeNull();
                exception.Should().BeNull();

                result.Payload.Should().BeEquivalentTo(testVector.Message);
                result.Timestamp.Should().Be(BrancaToken.GetDateTime(testVector.TimeStamp));
            }
            else
            {
                result.Should().BeNull();
                exception.Should().NotBeNull();
            }
        }

        public class TestBrancaTokenHandler : BrancaTokenHandler
        {
            public byte[] Nonce { get; set; }
            protected override byte[] GenerateNonce() => Nonce ?? base.GenerateNonce();
        }
        
        public class BrancaTestVector
        {
            public BrancaTestVector(JsonNode data)
            {
                Id = data["id"]!.GetValue<int>();
                Comment = data["comment"]?.GetValue<string>();
                Token = data["token"]?.GetValue<string>();
                TimeStamp = data["timestamp"]?.GetValue<uint>() ?? throw new Exception("Unable to parse timestamp");
                IsValid = data["isValid"]?.GetValue<bool>() ?? throw new Exception("Unable to parse isValid");

                var messageHex = data["msg"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(messageHex)) Message = Base16.Decode(messageHex);
                else Message = Array.Empty<byte>();
                
                var nonceHex = data["nonce"]?.GetValue<string>();
                if (!string.IsNullOrEmpty(nonceHex)) Nonce = Base16.Decode(nonceHex);
                
                var keyHex = data["key"]?.GetValue<string>() ?? throw new Exception("Failed to find key");
                Key = Base16.Decode(keyHex);
            }

            public int Id { get; }
            public string Comment { get; }
            public byte[] Key { get; }
            public byte[] Nonce { get; }
            public uint TimeStamp { get; }
            public string Token { get; }
            public byte[] Message { get; }
            public bool IsValid { get; }
        }
    }
}