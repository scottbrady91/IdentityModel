using System;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Tokens;

internal class EdDsaSignatureProvider : SignatureProvider 
{
    private readonly EdDsaSecurityKey edDsaKey;

    public EdDsaSignatureProvider(EdDsaSecurityKey key, string algorithm)
        : base(key, algorithm)
    {
        edDsaKey = key;
        WillCreateSignatures = key.PrivateKeyStatus == PrivateKeyStatus.Exists;
    }

    protected override void Dispose(bool disposing) { }
    public override byte[] Sign(byte[] input) => edDsaKey.EdDsa.Sign(input);
    public override bool Verify(byte[] input, byte[] signature) => edDsaKey.EdDsa.Verify(input, signature);
    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength) => edDsaKey.EdDsa.Verify(input, inputOffset, inputLength, signature, signatureOffset, signatureLength);
    
    public override bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        var signature = edDsaKey.EdDsa.Sign(data.ToArray());
        signature.CopyTo(destination);
        bytesWritten = signature.Length;
        return true;
    }

    public override byte[] Sign(byte[] input, int offset, int count)
    {
        var data = new byte[count];
        Buffer.BlockCopy(input, offset, data, 0, count);
        return edDsaKey.EdDsa.Sign(data);
    }
}