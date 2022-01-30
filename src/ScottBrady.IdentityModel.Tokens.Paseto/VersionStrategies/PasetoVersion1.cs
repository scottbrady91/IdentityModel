using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens.Paseto
{
    public class PasetoVersion1 : PasetoVersionStrategy
    {
        private const string PublicHeader = "v1.public.";
        
        public override string Encrypt(string payload, string footer, EncryptingCredentials encryptingCredentials)
        {
            throw new NotSupportedException("v1.public not supported");
        }

        public override string Sign(string payload, string footer, SigningCredentials signingCredentials)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (signingCredentials == null) throw new ArgumentNullException(nameof(signingCredentials));

            if (signingCredentials.Key.GetType() != typeof(RsaSecurityKey))
                throw new SecurityTokenInvalidSigningKeyException($"PASETO v1 requires a key of type {typeof(RsaSecurityKey)}");
            if (signingCredentials.Algorithm != SecurityAlgorithms.RsaSsaPssSha384)
                throw new SecurityTokenInvalidSigningKeyException($"PASETO v1 requires a key for configured for the '{SecurityAlgorithms.RsaSsaPssSha384}' algorithm");

            var privateKey = (RsaSecurityKey) signingCredentials.Key;
            if (privateKey.PrivateKeyStatus != PrivateKeyStatus.Exists)
                throw new SecurityTokenInvalidSigningKeyException($"Missing private key");
            
            var payloadBytes = Encoding.UTF8.GetBytes(payload);
            
            var messageToSign = PreAuthEncode(new[]
            {
                Encoding.UTF8.GetBytes(PublicHeader),
                payloadBytes,
                Encoding.UTF8.GetBytes(footer ?? string.Empty)
            });

            var signature = privateKey.Rsa.SignData(messageToSign, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
            
            var token = $"{PublicHeader}{Base64UrlEncoder.Encode(payloadBytes.Combine(signature))}";
            if (!string.IsNullOrWhiteSpace(footer)) token += $".{Base64UrlEncoder.Encode(footer)}";

            return token;
        }

        public override PasetoSecurityToken Decrypt(PasetoToken token, IEnumerable<SecurityKey> decryptionKeys)
        {
            throw new NotSupportedException("v1.public not supported");
        }

        public override PasetoSecurityToken Verify(PasetoToken token, IEnumerable<SecurityKey> signingKeys)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (signingKeys == null || !signingKeys.Any()) throw new ArgumentNullException(nameof(signingKeys));

            var keys = signingKeys.OfType<RsaSecurityKey>().ToList();
            if (!keys.Any()) throw new SecurityTokenInvalidSigningKeyException($"PASETO v1 requires key of type {typeof(RsaSecurityKey)}");
            
            if (token.Version != PasetoConstants.Versions.V1) throw new ArgumentException("Invalid PASETO version");
            if (token.Purpose != PasetoConstants.Purposes.Public) throw new ArgumentException("Invalid PASETO purpose");
            
            // decode payload
            var payload = Base64UrlEncoder.DecodeBytes(token.EncodedPayload);
            if (payload.Length < 256) throw new SecurityTokenInvalidSignatureException("Payload does not contain signature");
            
            // extract signature from payload (rightmost 64 bytes)
            var signature = new byte[256];
            Buffer.BlockCopy(payload, payload.Length - 256, signature, 0, 256);
            
            // decode payload JSON
            var message = new byte[payload.Length - 256];
            Buffer.BlockCopy(payload, 0, message, 0, payload.Length - 256);
            token.SetPayload(Encoding.UTF8.GetString(message));
            
            // pack
            var signedMessage = PreAuthEncode(new[]
            {
                Encoding.UTF8.GetBytes(PublicHeader), 
                message,
                Base64UrlEncoder.DecodeBytes(token.EncodedFooter ?? string.Empty)
            });
            
            // verify signature using valid keys
            foreach (var publicKey in keys)
            {
                try
                {
                    var isValidSignature = publicKey.Rsa.VerifyData(signedMessage, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
                    if (isValidSignature) return new PasetoSecurityToken(token);
                }
                catch (Exception)
                {
                    // ignored
                }
            }
            
            throw new SecurityTokenInvalidSignatureException("Invalid PASETO signature");
        }
    }
}