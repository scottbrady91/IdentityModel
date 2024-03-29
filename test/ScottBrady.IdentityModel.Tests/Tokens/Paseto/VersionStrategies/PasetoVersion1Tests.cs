using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens.Paseto;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto;

public class PasetoVersion1Tests
{
    private const string ValidVersion = "v1";
    private const string ValidPublicPurpose = "public";
    private const string ValidPublicPayload = "eyJzdWIiOiIxMjMiLCJleHAiOiIyMDIwLTA1LTA3VDE3OjExOjM4LjM3MTE3MTJaIn1HginqDCa4m01vI75OaWrFyAYCA1k9_sx36XVDEcHosOkk6coBDwDfoOaSFA_wE3nkfyuy3fTr7g6BpdzPbIb5qhI4Wpdy_zhhyEz7kC8ZSaDNN0tnBT0sL1c6hSuWKGh3tT6qPmjUmJwIv2ZjosozSmRF7bhWKJDsvTzQN6EFBddcvQpPQok9Ekdgzd70_Yxjl9YlUizF7WOiDm-R6m3xy_Mk8IRGQwiArYGmJRmR82W97ajqdBUJD8kbaFQglDxwEMcX-T4AqXCttjhdQi-JcXX34SDTyxE-8m02X8eNrKg64L6ZAFDAzbaa2bz3EUo5ULW2XaG4DW2zZ4nFd9m2";
    private readonly string validToken = $"{ValidVersion}.{ValidPublicPurpose}.{ValidPublicPayload}";

    private const string ValidSigningPrivateKey =
        "PFJTQUtleVZhbHVlPjxNb2R1bHVzPm9VQ002dEdieFc5eGZqWm1mbmQzTThLQkFzd0ZmbHVLY2IwV1RNMXMzeVh2c3dZci9MbkFVVGVhNjF4QWRma3BSbVVuT3VrODRwZUN5OEVkMzdZcXVHL05WMldsT0dRckxMRkh3UklIMGdmU0IzMjFpdlVzN2xqbDc5S25TRmpEU0ZqcUJNTEJTSS93ZlhobCtYTGZrTjczaGJmeTNSRzVTUDU4Vm5UUEQveWFRczlmNVdVVHhCSFBKNWx4Ump3cVpTemJjZE05cHNtcVFHWGcveUVCejFsMlJQaCtTK0R1aEw5TU1iRWdTb0lXanFKaWEzUFllRDF5WEt3RjlPdjlaa3V4L21ZZjRkRW9pWUZXV05jS3ZSSGFTVFBjTFd0NnZpUXZsekREd09FUG9HdlI4SkNreUJ2a1J0Q1VBeVAyMEpkYzFGK0xqdEp3dkIyNTRBTjU1UT09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48UD54Mlp3Y1N1Ni9KeTB5UFRqcVJXTlA1OVhtMk5hNDFEajdQeThsNHBXbWZKWkExTWxBMzRMNUpLVEpJMHZEWStyMTBhN1JRcVJSeHpseEVnQStvMHQwbW5uckRZbGJYbDB4OGlON04vb2w2OHZ0NEJtWFZCWGdxYURpNUJoaWtvLzVzd3EvOVhBd1ZKYm1zVFBCSjVGdi9DQWxUSytNbStacUt6MzlHVTYvMHM9PC9QPjxRPnp3WU80MVdGRUFyTS80R3hDOW1HZEhJeEFKR2RBaWoyZWJ0NjMrQk9QRUxpelZySjdudVR0ZGtxZnlhRHR5eXpGTWxVRHV2VVpIMU1YNnlsUldsQWQrSlhZcUFRZVlML2poYXZYL0llL2NsRE5YRnlRbTNoeitrOFRZZDV2KzFId0RjVTNWVUJlQnVTa3d3bmgrSXBHMU5HeWk4b0RJZldYZThIUXRsdVBZOD08L1E+PERQPllPbGN4T1FvSVJaWWwwTE9VeU55WHZXbXNwTDdYWGUzRHp0V3ZhQXlydWVtYzRNNWZoVUkycktTYVRWbEpRWXEwcHBCOGpCTW8yOWNES1dpTkNQaG5WNXpock5hUlhhK1Ywc1dENFpUbVVVL3Y4UGIvSVpMd2VnRUR4VEJFMkU2NVlWZGNMSUcyTzZhTHdKd1N5SlJiQlFMcW5mYkVOQkVza0krMEwxU2l6az08L0RQPjxEUT5XRTJyT0FpWVV6bG9LMnYwU3F1a0VETk05NE1reDNFVmdPTVpERGt1NWNGWjRHSGpWQmZkNzJrTUdXUWlOcFdZWlR0aTRXSnlHOUxlS3NrSFRjNFJNNUdWMkhtUnpXSzFBclJtWmJSdXg2MTdQMlorYUJ0YWdFWnA5Ri9lN0tDWFJFTzZZSllMcEdHT2FhNTdoaGhQbEZvM0RiS0RrS1M0S1NUMW9ld0FlNzA9PC9EUT48SW52ZXJzZVE+SVpvNFVZRzVOVWt6TlA3LzVXTzhkVW9BUFJJU2htVithNTh5dWZWRjZtMUl3NTRJVDNTVWhXOVh5dFdMa0ZsWmJZakhxMmZlaUhDOUw0OGFUTG1SMmlIejVKUjJKN2pENnJGbis1SFNZR2l0OGpZbnBvNGpvVjZwaDAraWhOVnMzbkk3OEZVcFhmVDdWd0hhZDF4SXJ0QzA0VHBPODFjSjZpbi91TTRBVDI4PTwvSW52ZXJzZVE+PEQ+bEtQSEFmR2prRlJSSHRHUW13VU9pVlRDelV3NXlDY2pzQUpuMnZZRlpKRTRxaUtIUzVnQ0VodWFuMWZUUjZ3Y2d2cGROaTJuWlF2YWttMTZWeXc1cHZmUUpiN1psT2lvNzdLZS9QYmM1SnMyM0piaFVLejk5TnRYWVVFaDJFdVIvMCtPc0VMQ0hsd29oOUFDMS9VdTVnRFIwNTRqcmVwWGpGU2hVcVNyOWdRaG5sejhreHlhdUpaK3hKQWorSWVnd3lzRkp0ZWVLUldJZjdDZ3ZESFZrMk8rcjBJcTZldTBWTFMxbHladlNNOWJyWDlxOVRYUzMvODJFQ2M2UW9PbUk5NEFTOXhmcGZWeGIyZjJEQ0dSN0dZL1M2WWJTRGpJMXpMQWxQRzZiWVJRTFlsR1FVd3NvdHkrYzFZK1ZCc1R3VEk4WTFneTVOemdES2x6S3I3ZXhRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=";
    private const string ValidSigningPublicKey =
        "PFJTQUtleVZhbHVlPjxNb2R1bHVzPm9VQ002dEdieFc5eGZqWm1mbmQzTThLQkFzd0ZmbHVLY2IwV1RNMXMzeVh2c3dZci9MbkFVVGVhNjF4QWRma3BSbVVuT3VrODRwZUN5OEVkMzdZcXVHL05WMldsT0dRckxMRkh3UklIMGdmU0IzMjFpdlVzN2xqbDc5S25TRmpEU0ZqcUJNTEJTSS93ZlhobCtYTGZrTjczaGJmeTNSRzVTUDU4Vm5UUEQveWFRczlmNVdVVHhCSFBKNWx4Ump3cVpTemJjZE05cHNtcVFHWGcveUVCejFsMlJQaCtTK0R1aEw5TU1iRWdTb0lXanFKaWEzUFllRDF5WEt3RjlPdjlaa3V4L21ZZjRkRW9pWUZXV05jS3ZSSGFTVFBjTFd0NnZpUXZsekREd09FUG9HdlI4SkNreUJ2a1J0Q1VBeVAyMEpkYzFGK0xqdEp3dkIyNTRBTjU1UT09PC9Nb2R1bHVzPjxFeHBvbmVudD5BUUFCPC9FeHBvbmVudD48L1JTQUtleVZhbHVlPg==";

    private readonly SigningCredentials validSigningCredentials;
    private readonly List<SecurityKey> validVerificationKeys;
        
    private readonly PasetoVersion1 sut = new PasetoVersion1();

    public PasetoVersion1Tests()
    {
        var privateKey = RSA.Create();
        privateKey.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(ValidSigningPrivateKey)));

        var publicKey = RSA.Create();
        publicKey.FromXmlString(Encoding.UTF8.GetString(Convert.FromBase64String(ValidSigningPublicKey)));

        validSigningCredentials = new SigningCredentials(new RsaSecurityKey(privateKey), SecurityAlgorithms.RsaSsaPssSha384);
        validVerificationKeys = new List<SecurityKey> {new RsaSecurityKey(publicKey)};
    }
        
    [Fact]
    public void Sign_WhenPayloadIsNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => sut.Sign(null, null, validSigningCredentials));

    [Fact]
    public void Sign_WhenSigningCredentialsAreNull_ExpectArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => sut.Sign("test", null, null));

    [Fact]
    public void Sign_WhenSigningCredentialsDoNotContainRsaSecurityKey_ExpectSecurityTokenInvalidSigningKeyException()
    {
        var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(ECDsa.Create()), SecurityAlgorithms.EcdsaSha256);

        Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Sign("payload", null, signingCredentials));
    }

    [Fact]
    public void Sign_WhenSigningCredentialsNotConfiguredForPs384_ExpectSecurityTokenInvalidSigningKeyException()
    {
        var signingCredentials = new SigningCredentials(validSigningCredentials.Key, SecurityAlgorithms.RsaSha384);

        Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Sign("payload", null, signingCredentials));
    }

    [Fact]
    public void Sign_WhenSigningCredentialsDoNotContainPrivateKey_ExpectSecurityTokenInvalidSigningKeyException()
    {
        var signingCredentials = new SigningCredentials(validVerificationKeys.First(), SecurityAlgorithms.RsaSsaPssSha384);

        Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Sign("payload", null, signingCredentials));   
    }

    [Fact]
    public void Sign_WhenTokenGenerated_ExpectThreeParts()
    {
        var token = sut.Sign("payload", null, validSigningCredentials);

        token.Split('.').Length.Should().Be(3);
    }

    [Fact]
    public void Sign_WhenTokenGeneratedWithFooter_ExpectFourParts()
    {
        var token = sut.Sign("payload", "footer", validSigningCredentials);

        token.Split('.').Length.Should().Be(4);
    }
        
    [Fact]
    public void Verify_WhenTokenIsNull_ExpectArgumentNullException() 
        => Assert.Throws<ArgumentNullException>(() => sut.Verify(null, validVerificationKeys));
        
    [Fact]
    public void Verify_WhenSecurityKeysAreNull_ExpectArgumentNullException() 
        => Assert.Throws<ArgumentNullException>(() => sut.Verify(new PasetoToken(validToken), null));
        
    [Fact]
    public void Verify_WhenSecurityKeysAreEmpty_ExpectArgumentNullException() 
        => Assert.Throws<ArgumentNullException>(() => sut.Verify(new PasetoToken(validToken), new List<SecurityKey>()));
        
    [Fact]
    public void Verify_WhenNoRsaSecurityKeysPresent_ExpectSecurityTokenInvalidSigningKeyException()
    {
        var keys = new List<SecurityKey> {new ECDsaSecurityKey(ECDsa.Create())};

        Assert.Throws<SecurityTokenInvalidSigningKeyException>(() => sut.Verify(new PasetoToken(validToken), keys));
    }
        
    [Fact]
    public void Verify_WhenIncorrectVersion_ExpectArgumentException()
    {
        var token = new PasetoToken($"v42.{ValidPublicPurpose}.{ValidPublicPayload}");

        Assert.Throws<ArgumentException>(() => sut.Verify(token, validVerificationKeys));
    }
        
    [Fact]
    public void Verify_WhenIncorrectPurpose_ExpectArgumentException()
    {
        var token = new PasetoToken($"{ValidVersion}.local.{ValidPublicPayload}");

        Assert.Throws<ArgumentException>(() => sut.Verify(token, validVerificationKeys));
    }

    [Fact]
    public void Verify_WhenPayloadDoesNotContainEnoughBytes_ExpectSecurityTokenInvalidSignatureException()
    {
        var payloadBytes = new byte[32];
        new Random().NextBytes(payloadBytes);
            
        var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.{Base64UrlEncoder.Encode(payloadBytes)}");
            
        Assert.Throws<SecurityTokenInvalidSignatureException>(() => sut.Verify(token, validVerificationKeys));
    }

    [Fact]
    public void Verify_WhenPayloadDoesNotContainJson_ExpectSecurityTokenException()
    {
        var payloadValue = "<xml>test</xml>";
        var payloadValueBytes = Encoding.UTF8.GetBytes(payloadValue);
            
        var signature = new byte[256];
        new Random().NextBytes(signature);

        var payload = new byte[payloadValueBytes.Length + signature.Length];
        Buffer.BlockCopy(payloadValueBytes, 0, payload, 0, payloadValueBytes.Length);
        Buffer.BlockCopy(signature, 0, payload, payloadValueBytes.Length, signature.Length);

        var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.{Base64UrlEncoder.Encode(payload)}");

        Assert.Throws<ArgumentException>(() => sut.Verify(token, validVerificationKeys));
    }

    [Fact]
    public void Verify_WhenSignatureInvalid_ExpectSecurityTokenInvalidSignatureException()
    {
        var payloadValue = "{ \"test\": \"test\" }";
        var payloadValueBytes = Encoding.UTF8.GetBytes(payloadValue);
            
        var signature = new byte[256];
        new Random().NextBytes(signature);

        var payload = new byte[payloadValueBytes.Length + signature.Length];
        Buffer.BlockCopy(payloadValueBytes, 0, payload, 0, payloadValueBytes.Length);
        Buffer.BlockCopy(signature, 0, payload, payloadValueBytes.Length, signature.Length);

        var token = new PasetoToken($"{ValidVersion}.{ValidPublicPurpose}.{Base64UrlEncoder.Encode(payload)}");

        Assert.Throws<SecurityTokenInvalidSignatureException>(() => sut.Verify(token, validVerificationKeys));
    }

    [Fact]
    public void Verify_WhenSignatureIsValid_ExpectCorrectSecurityToken()
    {
        var token = new PasetoToken(validToken);

        var securityToken = sut.Verify(token, validVerificationKeys);

        securityToken.Should().NotBeNull();
        securityToken.RawToken.Should().Be(token.RawToken);
    }

    [Fact]
    public void SignAndVerify_WhenKeysAreValid_ExpectCorrectClaimsFromPayload()
    {
        const string expectedClaimType = "test";
        const string expectedClaimValue = "test_val";
        var expectedPayload = $"{{ \"{expectedClaimType}\": \"{expectedClaimValue}\" }}";

        var token = sut.Sign(expectedPayload, null, validSigningCredentials);
        var parsedToken = sut.Verify(new PasetoToken(token), validVerificationKeys);

        parsedToken.Claims.Should().Contain(x => x.Type == expectedClaimType && x.Value == expectedClaimValue);
        parsedToken.RawToken.Should().Be(token);
    }

    [Fact]
    public void SignAndVerify_WhenKeysAreValidAndWithFooter_ExpectCorrectClaimsFromPayloadAndCorrectFooter()
    {
        const string expectedClaimType = "test";
        const string expectedClaimValue = "test_val";
        const string expectedFooter = "{\"kid\": \"123\"}";
        var expectedPayload = $"{{ \"{expectedClaimType}\": \"{expectedClaimValue}\" }}";

        var token = sut.Sign(expectedPayload, expectedFooter, validSigningCredentials);
        var parsedToken = sut.Verify(new PasetoToken(token), validVerificationKeys);

        parsedToken.Claims.Should().Contain(x => x.Type == expectedClaimType && x.Value == expectedClaimValue);
        parsedToken.RawToken.Should().Be(token);
        parsedToken.Footer.Should().Be(expectedFooter);
    }
}