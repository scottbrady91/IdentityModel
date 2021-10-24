using System;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens.Branca;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Branca
{
    /// <summary>
    /// Test vectors from branca-js implementation
    /// </summary>
    public class BrancaTestVectors
    {
        private readonly byte[] key = System.Text.Encoding.UTF8.GetBytes("supersecretkeyyoushouldnotcommit");
        
        [Fact]
        public void ValidateToken_TestTokenWithHelloWorldAndZeroTimestamp()
        {
            const string token = "870S4BYjk7NvyViEjUNsTEmGXbARAX9PamXZg0b3JyeIdGyZkFJhNsOQW6m0K9KnXt3ZUBqDB6hF4";
            
            var handler = new BrancaTokenHandler();
            var decryptedToken = handler.DecryptToken(token, key);

            decryptedToken.Payload.Should().Be("Hello world!");
            decryptedToken.Timestamp.Should().Be(DateTimeOffset.FromUnixTimeSeconds(0).UtcDateTime);
        }
        
        [Fact]
        public void ValidateToken_TestTokenWithHelloWorldAndMaxTimestamp()
        {
            const string token = "89i7YCwtsSiYfXvOKlgkCyElnGCOEYG7zLCjUp4MuDIZGbkKJgt79Sts9RdW2Yo4imonXsILmqtNb";
            
            var handler = new BrancaTokenHandler();
            var decryptedToken = handler.DecryptToken(token, key);

            decryptedToken.Payload.Should().Be("Hello world!");
            decryptedToken.Timestamp.Should().Be(DateTimeOffset.FromUnixTimeSeconds(4294967295).UtcDateTime);
        }
        
        [Fact]
        public void ValidateToken_TestTokenWithHelloWorldAndNovember27Timestamp()
        {
            const string token = "875GH234UdXU6PkYq8g7tIM80XapDQOH72bU48YJ7SK1iHiLkrqT8Mly7P59TebOxCyQeqpMJ0a7a";
            
            var handler = new BrancaTokenHandler();
            var decryptedToken = handler.DecryptToken(token, key);

            decryptedToken.Payload.Should().Be("Hello world!");
            decryptedToken.Timestamp.Should().Be(DateTimeOffset.FromUnixTimeSeconds(123206400).UtcDateTime);
        }
        
        [Fact]
        public void ValidateToken_TestTokenWithEightNullBytesAndZeroTimestamp()
        {
            const string token = "1jIBheHWEwYIP59Wpm4QkjkIKuhc12NcYdp9Y60B6av7sZc3vJ5wBwmKJyQzGfJCrvuBgGnf";
            
            var handler = new BrancaTokenHandler();
            var decryptedToken = handler.DecryptToken(token, key);

            decryptedToken.Payload.Should().Be(System.Text.Encoding.UTF8.GetString(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}));
            decryptedToken.Timestamp.Should().Be(DateTimeOffset.FromUnixTimeSeconds(0).UtcDateTime);
        }
        
        [Fact]
        public void ValidateToken_TestTokenWithEightNullBytesAndMaxTimestamp()
        {
            const string token = "1jrx6DUq9HmXvYdmhWMhXzx3klRzhlAjsc3tUFxDPCvZZLm16GYOzsBG4KwF1djjW1yTeZ2B";
            
            var handler = new BrancaTokenHandler();
            var decryptedToken = handler.DecryptToken(token, key);

            decryptedToken.Payload.Should().Be(System.Text.Encoding.UTF8.GetString(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}));
            decryptedToken.Timestamp.Should().Be(DateTimeOffset.FromUnixTimeSeconds(4294967295).UtcDateTime);
        }
        
        [Fact]
        public void ValidateToken_TestTokenWithEightNullBytesAndNovember27Timestamp()
        {
            const string token = "1jJDJOEfuc4uBJh5ivaadjo6UaBZJDZ1NsWixVCz2mXw3824JRDQZIgflRqCNKz6yC7a0JKC";
            
            var handler = new BrancaTokenHandler();
            var decryptedToken = handler.DecryptToken(token, key);

            decryptedToken.Payload.Should().Be(System.Text.Encoding.UTF8.GetString(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}));
            decryptedToken.Timestamp.Should().Be(DateTimeOffset.FromUnixTimeSeconds(123206400).UtcDateTime);
        }
        
        [Fact]
        public void ValidateToken_TestTokenWithWrongVersion()
        {
            const string token = "89mvl3RkwXjpEj5WMxK7GUDEHEeeeZtwjMIOogTthvr44qBfYtQSIZH5MHOTC0GzoutDIeoPVZk3w";
            
            var handler = new BrancaTokenHandler();
            var exception = Assert.Throws<SecurityTokenException>(() => handler.DecryptToken(token, key));
            
            exception.Message.Should().Be("Unsupported Branca version");
        }

        [Fact]
        public void ValidateToken_CiphertextModification_ExpectSecurityTokenException()
        {
            var handler = new BrancaTokenHandler();
            
            var token = handler.CreateToken("test", key);
            var decoded = Base62.Decode(token);
            decoded[decoded.Length - 17] ^= 1; // Last byte before the Poly1305 tag

            Assert.Throws<CryptographicException>(() => handler.DecryptToken(Base62.Encode(decoded), key));
        }
    }
}