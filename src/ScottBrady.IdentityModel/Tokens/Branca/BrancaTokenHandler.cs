using System;
using System.Collections.Generic;
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
using ScottBrady.IdentityModel.Crypto;
using SecurityAlgorithms = ScottBrady.IdentityModel.Crypto.SecurityAlgorithms;

namespace ScottBrady.IdentityModel.Tokens
{
    public class BrancaTokenHandler : JwtPayloadTokenHandler
    {
        public override bool CanReadToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return false;
            if (token.Length > MaximumTokenSizeInBytes) return false;
            if (token.Any(x => !Base62.CharacterSet.Contains(x))) return false;

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

            if (!IsValidKey(tokenDescriptor.EncryptingCredentials))
                throw new SecurityTokenEncryptionFailedException(
                    "Invalid encrypting credentials. Branca tokens require a symmetric key using the XC20P algorithm and no key wrapping");

            var jwtStylePayload = tokenDescriptor.ToJwtPayload();

            // Remove iat claim in favour of timestamp
            var jObject = JObject.Parse(jwtStylePayload);
            jObject.Remove(JwtRegisteredClaimNames.Iat);

            var symmetricKey = (SymmetricSecurityKey) tokenDescriptor.EncryptingCredentials.Key;

            return CreateToken(jObject.ToString(Formatting.None), symmetricKey.Key);
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
            if (!CanReadToken(token)) throw new InvalidCastException("Unable to read token");
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

        public override TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(token)) return new TokenValidationResult {Exception = new ArgumentNullException(nameof(token))};
            if (validationParameters == null) return new TokenValidationResult {Exception = new ArgumentNullException(nameof(validationParameters))};
            if (!CanReadToken(token)) return new TokenValidationResult {Exception = new SecurityTokenException("Unable to read token")};

            // get decryption keys
            var securityKeys = GetBrancaDecryptionKeys(token, validationParameters);

            BrancaToken decryptedToken = null;

            foreach (var securityKey in securityKeys)
            {
                try
                {
                    decryptedToken = DecryptToken(token, securityKey.Key);
                    if (decryptedToken != null) break;
                }
                catch (Exception)
                {
                    // ignored
                }
            }

            if (decryptedToken == null)
                return new TokenValidationResult {Exception = new SecurityTokenDecryptionFailedException("Unable to decrypt token")};

            BrancaSecurityToken brancaToken;
            try
            {
                brancaToken = new BrancaSecurityToken(decryptedToken);
            }
            catch (Exception e)
            {
                return new TokenValidationResult {Exception = e};
            }

            var innerValidationResult = ValidateTokenPayload(brancaToken, validationParameters);
            if (!innerValidationResult.IsValid) return innerValidationResult;

            var identity = innerValidationResult.ClaimsIdentity;
            if (validationParameters.SaveSigninToken) identity.BootstrapContext = token;

            return new TokenValidationResult
            {
                SecurityToken = brancaToken,
                ClaimsIdentity = identity,
                IsValid = true
            };
        }

        protected virtual IEnumerable<SymmetricSecurityKey> GetBrancaDecryptionKeys(string token, TokenValidationParameters validationParameters)
        {
            var keys = base.GetDecryptionKeys(token, validationParameters);
            
            return keys.Where(IsValidKey).Select(x => (SymmetricSecurityKey) x).ToList();
        }

        protected virtual bool IsValidKey(byte[] key) => key?.Length == 32;

        protected virtual bool IsValidKey(SecurityKey securityKey)
        {
            if (securityKey == null) return false;
            if (!(securityKey is SymmetricSecurityKey symmetricKey)) return false;

            return IsValidKey(symmetricKey.Key);
        }

        protected virtual bool IsValidKey(EncryptingCredentials credentials)
        {
            if (credentials == null) return false;
            if (credentials.Enc != SecurityAlgorithms.XChaCha20Poly1305) return false;
            if (string.IsNullOrWhiteSpace(credentials.Alg)
                || credentials.Alg != Microsoft.IdentityModel.Tokens.SecurityAlgorithms.None)
            {
                return false;
            }

            return IsValidKey(credentials.Key);
        }

        private static byte[] GuaranteedRead(Stream stream, int length)
        {
            if (!stream.TryRead(length, out var bytes)) throw new SecurityTokenException("");
            return bytes;
        }
    }
}