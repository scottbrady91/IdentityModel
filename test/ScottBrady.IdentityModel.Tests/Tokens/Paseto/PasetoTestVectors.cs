using System;
using System.IO;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.Paseto
{
    public class PasetoTestVectors
    {
        [Fact]
        public void ValidateToken_V1_S_1()
        {
            const string token = "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw" +
                                 "iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5k" +
                                 "iAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEt" +
                                 "m2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJ" +
                                 "zVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96Sf" +
                                 "Q6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1" +
                                 "QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtp" +
                                 "flZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw";
            const string pem = "-----BEGIN PUBLIC KEY-----\n" +
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p\n" +
                               "5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd\n" +
                               "74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g\n" +
                               "mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU\n" +
                               "5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5\n" +
                               "IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc\n" +
                               "p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB\n" +
                               "-----END PUBLIC KEY-----";
            // payload = "{ data: \"this is a signed message\", exp: \"2019-01-01T00:00:00+00:00\" }";

            var reader = new PemReader(new StringReader(pem));
            var pemObject = (RsaKeyParameters) reader.ReadObject();

            var rsaKey = RSA.Create(DotNetUtilities.ToRSAParameters(pemObject));

            var handler = new PasetoTokenHandler();
            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                
                IssuerSigningKey = new RsaSecurityKey(rsaKey)
            });

            result.IsValid.Should().BeTrue();
        }
        
        [Fact]
        public void ValidateToken_V1_S_2()
        {
            const string token = "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw" +
                                 "iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4mis" +
                                 "AuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X" +
                                 "8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S" +
                                 "1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthq" +
                                 "az7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJM" +
                                 "pixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C" +
                                 "0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJ" +
                                 "kWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVx" +
                                 "biJ9";
            const string pem = "-----BEGIN PUBLIC KEY-----\n" +
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p\n" +
                               "5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd\n" +
                               "74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g\n" +
                               "mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU\n" +
                               "5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5\n" +
                               "IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc\n" +
                               "p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB\n" +
                               "-----END PUBLIC KEY-----";
            // {"data":"this is a signed message", "exp":"2019-01-01T00:00:00+00:00"}
            // footer = {"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}

            var reader = new PemReader(new StringReader(pem));
            var pemObject = (RsaKeyParameters) reader.ReadObject();

            var rsaKey = RSA.Create(DotNetUtilities.ToRSAParameters(pemObject));

            var handler = new PasetoTokenHandler();
            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                
                IssuerSigningKey = new RsaSecurityKey(rsaKey)
            });

            result.IsValid.Should().BeTrue();
        }

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