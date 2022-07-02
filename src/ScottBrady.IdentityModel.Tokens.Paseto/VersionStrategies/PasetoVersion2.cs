using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Signers;
using ScottBrady.IdentityModel.Crypto;

namespace ScottBrady.IdentityModel.Tokens.Paseto
{
    public class PasetoVersion2 : PasetoVersionStrategy
    {
        private const string PublicHeader = "v2.public.";
        
        public override string Encrypt(string payload, string footer, EncryptingCredentials encryptingCredentials)
        {
            throw new NotSupportedException("v2.local not supported");
        }

        public override string Sign(string payload, string footer, SigningCredentials signingCredentials)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (signingCredentials == null) throw new ArgumentNullException(nameof(signingCredentials));

            if (signingCredentials.Key.GetType() != typeof(EdDsaSecurityKey))
                throw new SecurityTokenInvalidSigningKeyException($"PASETO v2 requires a key of type {typeof(EdDsaSecurityKey)}");
            if (signingCredentials.Algorithm != ExtendedSecurityAlgorithms.EdDsa)
                throw new SecurityTokenInvalidSigningKeyException($"PASETO v2 requires a key for configured for the '{ExtendedSecurityAlgorithms.EdDsa}' algorithm");

            var privateKey = (EdDsaSecurityKey) signingCredentials.Key;
            if (privateKey.PrivateKeyStatus != PrivateKeyStatus.Exists)
                throw new SecurityTokenInvalidSigningKeyException($"Missing private key");
            
            var payloadBytes = Encoding.UTF8.GetBytes(payload);

            var messageToSign = PreAuthEncode(new[]
            {
                Encoding.UTF8.GetBytes(PublicHeader),
                payloadBytes,
                Encoding.UTF8.GetBytes(footer ?? string.Empty)
            });
            
            var signer = new Ed25519Signer();
            signer.Init(true, privateKey.KeyParameters);
            signer.BlockUpdate(messageToSign, 0, messageToSign.Length);
            var signature = signer.GenerateSignature();

            var token = $"{PublicHeader}{Base64UrlEncoder.Encode(payloadBytes.Combine(signature))}";
            if (!string.IsNullOrWhiteSpace(footer)) token += $".{Base64UrlEncoder.Encode(footer)}";

            return token;
        }

        public override PasetoSecurityToken Decrypt(PasetoToken token, IEnumerable<SecurityKey> decryptionKeys)
        {
            throw new NotSupportedException("v2.local not supported");
        }

        public override PasetoSecurityToken Verify(PasetoToken token, IEnumerable<SecurityKey> signingKeys)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (signingKeys == null || !signingKeys.Any()) throw new ArgumentNullException(nameof(signingKeys));

            var keys = signingKeys.OfType<EdDsaSecurityKey>().ToList();
            if (!keys.Any()) throw new SecurityTokenInvalidSigningKeyException($"PASETO v2 requires key of type {typeof(EdDsaSecurityKey)}");
            
            if (token.Version != PasetoConstants.Versions.V2) throw new ArgumentException("Invalid PASETO version");
            if (token.Purpose != PasetoConstants.Purposes.Public) throw new ArgumentException("Invalid PASETO purpose");
            
            // decode payload
            var payload = Base64UrlEncoder.DecodeBytes(token.EncodedPayload);
            if (payload.Length < 64) throw new SecurityTokenInvalidSignatureException("Payload does not contain signature");

            // extract signature from payload (rightmost 64 bytes)
            var signature = new byte[64];
            Buffer.BlockCopy(payload, payload.Length - 64, signature, 0, 64);

            // decode payload JSON
            var message = new byte[payload.Length - 64];
            Buffer.BlockCopy(payload, 0, message, 0, payload.Length - 64);
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
                var signer = new Ed25519Signer();
                signer.Init(false, publicKey.KeyParameters);
                signer.BlockUpdate(signedMessage, 0, signedMessage.Length);
            
                var isValidSignature = signer.VerifySignature(signature);
                if (isValidSignature) return new PasetoSecurityToken(token);
            }

            throw new SecurityTokenInvalidSignatureException("Invalid PASETO signature");
        }
    }
}