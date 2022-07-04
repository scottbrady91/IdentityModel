using System;
using System.IO;
using System.Text.Json.Nodes;
using FluentAssertions;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA;

public class Rfc8032TestVectors
{
    public static readonly TheoryData<EdDsaTestVector> TestVectors = new TheoryData<EdDsaTestVector>();

    static Rfc8032TestVectors()
    {
        var file = File.OpenRead("Tokens/EdDsa/TestVectors/testvectors.json");
        var data = JsonNode.Parse(file);
        if (data == null) throw new Exception("Failed to load test vectors");

        foreach (var testVector in data.AsArray())
        {
            TestVectors.Add(new EdDsaTestVector(testVector));
        }
    }
    
    [Theory, MemberData(nameof(TestVectors))]
    public void SignAndVerify_ExpectValid(EdDsaTestVector testVector)
    {
        var privateKey = EdDsa.CreateFromPrivateKey(testVector.PrivateKey, testVector.Curve);
        var publicKey = EdDsa.CreateFromPublicKey(testVector.PublicKey, testVector.Curve);

        privateKey.Sign(testVector.Message).Should().BeEquivalentTo(testVector.Signature);
        publicKey.Verify(testVector.Message, testVector.Signature).Should().BeTrue();
    } 
}

public class EdDsaTestVector
{
    public EdDsaTestVector(JsonNode data)
    {
        Name = data["name"]?.GetValue<string>();
        
        var messageHex = data["message"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(messageHex)) Message = Base16.Decode(messageHex);
        else Message = Array.Empty<byte>();

        var privateKey = data["privateKey"]?.GetValue<string>() ?? throw new Exception("Failed to find privateKey");
        PrivateKey = Base16.Decode(privateKey);
        var publicKey = data["publicKey"]?.GetValue<string>() ?? throw new Exception("Failed to find publicKey");
        PublicKey = Base16.Decode(publicKey);
        var signature = data["signature"]?.GetValue<string>() ?? throw new Exception("Failed to find signature");
        Signature = Base16.Decode(signature);

        Curve = data["curve"]?.GetValue<string>() ?? throw new Exception("Failed to find curve");
    }
    
    public string Name { get; }
    public byte[] PrivateKey { get; }
    public byte[] PublicKey { get; }
    public byte[] Message { get; }
    public byte[] Signature { get; }
    public string Curve { get; }
    
}