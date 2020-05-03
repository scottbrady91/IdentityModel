using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    public class PasetoTestVectors
    {
        [Fact]
        public void ValidateToken_V2_S_1()
        {
            const string token = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw";
            const string publicKeyHex = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
            // payload = {"data":"this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}

            var handler = new PasetoTokenHandler();
            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                
                IssuerSigningKey = new EdDsaSecurityKey(new Ed25519PublicKeyParameters(HexToBytes(publicKeyHex), 0))
            });

            result.IsValid.Should().BeTrue();
        }
        
        [Fact]
        public void ValidateToken_V2_S_2()
        {
            const string token = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
            const string publicKeyHex = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
            // payload = {"data":"this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}
            // footer = {"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}

            var base64String = Convert.ToBase64String(HexToBytes(publicKeyHex));

            var handler = new PasetoTokenHandler();
            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                
                IssuerSigningKey = new EdDsaSecurityKey(new Ed25519PublicKeyParameters(HexToBytes(publicKeyHex), 0))
            });

            result.IsValid.Should().BeTrue();
        }

        private byte[] HexToBytes(string hex)
        {
            var hexAsBytes = new byte[hex.Length / 2];

            for (var i = 0; i < hex.Length; i += 2) {
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return hexAsBytes;
        }
    }
}