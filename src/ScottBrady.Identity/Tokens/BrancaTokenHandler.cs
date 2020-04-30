using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.Identity.BouncyCastle;
using ScottBrady.Identity.Extensions;

namespace ScottBrady.Identity.Tokens
{
    public class BrancaTokenHandler : TokenHandler
    {
        // public virtual TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
        
        // consider support for compression
        
        public virtual bool CanReadToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
            if (token.Length > MaximumTokenSizeInBytes) return false;
            if (token.Any(x => !Base62.CharacterSet.Contains(x))) return false;

            // check for invalid length? 1 + 4 + 24 + 16 - remainder should be divisible by 128
            
            return true;
        }

        /// <summary>
        /// Branca specification-level token generation
        /// </summary>
        /// <param name="payload">The payload to be encrypted into the Branca token</param>
        /// <param name="key">32-byte private key used to encrypt and decrypt the Branca token</param>
        /// <returns>Base62 encoded Branca Token</returns>
        public virtual string CreateToken(string payload, byte[] key)
        {
            if (string.IsNullOrWhiteSpace(payload)) throw new ArgumentNullException(nameof(payload));
            if (!IsValidKey(key)) throw new InvalidOperationException("Invalid encryption key");

            var nonce = new byte[24];
            RandomNumberGenerator.Create().GetBytes(nonce);

            var timestamp = Convert.ToUInt32(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            
            // header
            var header = new byte[29];
            using (var stream = new MemoryStream(header))
            {
                // version
                stream.WriteByte(0xBA);
                
                // timestamp
                stream.Write(BitConverter.GetBytes(timestamp), 0, 4);
                
                // nonce
                stream.Write(nonce, 0, nonce.Length);
            }
            
            var keyMaterial = new KeyParameter(key);
            var parameters = new ParametersWithIV(keyMaterial, nonce);

            var engine = new XChaChaEngine();
            engine.Init(true, parameters);

            var plaintextBytes = Encoding.UTF8.GetBytes(payload);
            var ciphertext = new byte[plaintextBytes.Length + 16];
            
            engine.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, ciphertext, 0);
            
            var poly = new Poly1305();
            poly.Init(keyMaterial);
            poly.BlockUpdate(header, 0, header.Length);
            poly.DoFinal(ciphertext, plaintextBytes.Length);

            var tokenBytes = new byte[header.Length + ciphertext.Length];
            Buffer.BlockCopy(header, 0, tokenBytes, 0, header.Length);
            Buffer.BlockCopy(ciphertext, 0, tokenBytes, header.Length, ciphertext.Length);
            
            return Base62.Encode(tokenBytes);
        }

        /// <summary>
        /// Creates Branca token using JWT rules
        /// </summary>
        /// <param name="tokenDescriptor">Token descriptor</param>
        /// <returns>Base62 encoded Branca Token</returns>
        public virtual string CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null) throw new ArgumentNullException(nameof(tokenDescriptor));

            JObject payload;
            if (tokenDescriptor.Subject != null)
            {
                // TODO
                payload = JObject.FromObject(tokenDescriptor.Subject.Claims.ToDictionary(x => x.Type, x => x.Value));
            }
            else
            {
                payload = new JObject();
            }

            if (tokenDescriptor.Claims != null && tokenDescriptor.Claims.Count > 0)
            {
                payload.Merge(JObject.FromObject(tokenDescriptor.Claims), new JsonMergeSettings {MergeArrayHandling = MergeArrayHandling.Replace});
            }

            if (tokenDescriptor.Audience != null)
            {
                // if (payload.TryGetValue(JwtRegisteredClaimNames.Aud, out var _))
                payload[JwtRegisteredClaimNames.Aud] = tokenDescriptor.Audience;
            }
            
            if (tokenDescriptor.Expires.HasValue)
            {
                // if (payload.ContainsKey(JwtRegisteredClaimNames.Exp))
                payload[JwtRegisteredClaimNames.Exp] = EpochTime.GetIntDate(tokenDescriptor.Expires.Value);
            }

            if (tokenDescriptor.Issuer != null)
            {
                // if (payload.ContainsKey(JwtRegisteredClaimNames.Iss))
                payload[JwtRegisteredClaimNames.Iss] = tokenDescriptor.Issuer;
            }

            if (tokenDescriptor.IssuedAt.HasValue)
            {
                // if (payload.ContainsKey(JwtRegisteredClaimNames.Iat))
                payload[JwtRegisteredClaimNames.Iat] = EpochTime.GetIntDate(tokenDescriptor.IssuedAt.Value);
            }

            if (tokenDescriptor.NotBefore.HasValue)
            {
                // if (payload.ContainsKey(JwtRegisteredClaimNames.Nbf))
                payload[JwtRegisteredClaimNames.Nbf] = EpochTime.GetIntDate(tokenDescriptor.NotBefore.Value);
            }
            
            /*var now = EpochTime.GetIntDate(DateTime.UtcNow);
            if (!payload.TryGetValue(JwtRegisteredClaimNames.Exp, out _))
                payload.Add(JwtRegisteredClaimNames.Exp, now + TimeSpan.FromMinutes(TokenLifetimeInMinutes).TotalSeconds);

            if (!payload.TryGetValue(JwtRegisteredClaimNames.Iat, out _))
                payload.Add(JwtRegisteredClaimNames.Iat, now);

            if (!payload.TryGetValue(JwtRegisteredClaimNames.Nbf, out _))
                payload.Add(JwtRegisteredClaimNames.Nbf, now);*/

            return CreateToken(payload.ToString(Formatting.None), (tokenDescriptor.EncryptingCredentials.Key as SymmetricSecurityKey).Key);
        }

        /// <summary>
        /// Branca specification level token decryption.
        /// </summary>
        /// <param name="token">Base62 encoded Branca token</param>
        /// <param name="key">32-byte private key used to encrypt and decrypt the Branca token</param>
        /// <returns>Pared and decrypted Branca Token</returns>
        public virtual BrancaToken DecryptToken(string token, byte[] key)
        {
            if (string.IsNullOrWhiteSpace(token)) throw new ArgumentNullException(nameof(token));
            if (!IsValidKey(key)) throw new InvalidOperationException("Invalid decryption key");
            
            var tokenBytes = Base62.Decode(token);

            using (var stream = new MemoryStream(tokenBytes, false))
            {
                // header
                var header = GuaranteedRead(stream, 29);
                
                byte[] nonce;
                uint timestamp;
                using (var headerStream = new MemoryStream(header))
                {
                    // version
                    var version = headerStream.ReadByte();
                    if (version != 0xBA) throw new SecurityTokenException("Unsupported Branca version");
                
                    // timestamp
                    var timestampBytes = GuaranteedRead(headerStream, 4);
                    timestamp = BitConverter.ToUInt32(timestampBytes, 0);
                    
                    // nonce
                    nonce = GuaranteedRead(headerStream, 24);
                }

                // ciphertext
                var ciphertextLength = (stream.Length - 16) - stream.Position;
                var ciphertext = GuaranteedRead(stream, (int) ciphertextLength);

                // tag
                var tag = GuaranteedRead(stream, 16);
                
                // XChaCha20-Poly1305
                var keyMaterial = new KeyParameter(key);
                var parameters = new ParametersWithIV(keyMaterial, nonce);
                
                var headerMac = new byte[16];
                var poly1305 = new Poly1305();
                poly1305.Init(keyMaterial);
                poly1305.BlockUpdate(header, 0, header.Length);
                poly1305.DoFinal(headerMac, 0);
                
                if (!headerMac.SequenceEqual(tag)) throw new SecurityTokenException("Invalid message authentication code");
                
                var engine = new XChaChaEngine();
                engine.Init(false, parameters);
                var decryptedPlaintext = new byte[ciphertext.Length];
                engine.ProcessBytes(ciphertext, 0, ciphertext.Length, decryptedPlaintext, 0);

                return new BrancaToken(
                    Encoding.UTF8.GetString(decryptedPlaintext), 
                    timestamp);
            }
        }
        
        protected virtual bool IsValidKey(byte[] key) => key?.Length == 32;

        protected virtual bool IsValidKey(EncryptingCredentials encryptingCredentials)
        {
            if (encryptingCredentials == null) return false;
            if (!(encryptingCredentials.Key is AsymmetricSecurityKey key)) return false;
            if (key.KeySize != 32) return false;

            return true;
        }

        private static byte[] GuaranteedRead(Stream stream, int length)
        {
            if (!stream.TryRead(length, out var bytes)) throw new SecurityTokenException("");
            return bytes;
        }
    }
}