using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    /// <summary>
    /// https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md
    /// </summary>
    public class PasetoVersionStrategyTests
    {
        [Fact]
        public void PreAuthEncode_WhenPiecesIsNull_ExpectArgumentNullException()
            => Assert.Throws<ArgumentNullException>(() => TestPasetoVersionStrategy.PreAuthEncodeSpy(null));

        [Fact]
        public void PreAuthEncodeSpy_WhenEmptyCollection_ExpectKnownResponse()
        {
            var encodedValue = TestPasetoVersionStrategy.PreAuthEncodeSpy(new List<byte[]>());
            encodedValue.Should().BeEquivalentTo(new byte[] {0, 0, 0, 0, 0, 0, 0, 0});
        }
        
        [Fact]
        public void PreAuthEncodeSpy_WhenEmptyString_ExpectKnownResponse()
        {
            var encodedValue = TestPasetoVersionStrategy.PreAuthEncodeSpy(new[] {System.Text.Encoding.UTF8.GetBytes(string.Empty)});
            encodedValue.Should().BeEquivalentTo(new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        }
        
        [Fact]
        public void PreAuthEncodeSpy_WhenTestString_ExpectKnownResponse()
        {
            var testBytes = System.Text.Encoding.UTF8.GetBytes("test");
            
            var encodedValue = TestPasetoVersionStrategy.PreAuthEncodeSpy(new[] {testBytes});
            encodedValue.Should().BeEquivalentTo(new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0}.Concat(testBytes));
        }
    }
    
    public class TestPasetoVersionStrategy : PasetoVersionStrategy
    {
        public override string Encrypt(string payload, string footer, EncryptingCredentials encryptingCredentials) => throw new NotImplementedException();
        public override string Sign(string payload, string footer, SigningCredentials signingCredentials) => throw new NotImplementedException();
        public override PasetoSecurityToken Decrypt(PasetoToken token, IEnumerable<SecurityKey> decryptionKeys) => throw new System.NotImplementedException();
        public override PasetoSecurityToken Verify(PasetoToken token, IEnumerable<SecurityKey> signingKeys) => throw new System.NotImplementedException();

        public static byte[] PreAuthEncodeSpy(IReadOnlyList<byte[]> pieces) => PreAuthEncode(pieces);
    }
}