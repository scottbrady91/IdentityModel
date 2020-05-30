using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Signers;

namespace ScottBrady.IdentityModel.Tokens
{
    internal class EdDsaSignatureProvider : SignatureProvider 
    {
        private readonly EdDsaSecurityKey edDsaKey;

        public EdDsaSignatureProvider(EdDsaSecurityKey key, string algorithm)
            : base(key, algorithm)
        {
            edDsaKey = key;
        }

        protected override void Dispose(bool disposing) { }
        
        public override byte[] Sign(byte[] input)
        {
            var signer = new Ed25519Signer();
            signer.Init(true, edDsaKey.KeyParameters);
            signer.BlockUpdate(input, 0, input.Length);

            return signer.GenerateSignature();
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            var validator = new Ed25519Signer();
            validator.Init(false, edDsaKey.KeyParameters);
            validator.BlockUpdate(input, 0, input.Length);

            return validator.VerifySignature(signature);
        }
    }
}