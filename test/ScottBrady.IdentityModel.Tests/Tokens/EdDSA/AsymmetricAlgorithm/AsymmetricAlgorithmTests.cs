using System;
using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Tokens.EdDSA.AsymmetricAlgorithm;

public class AsymmetricAlgorithmTests : EdDsaTestBase
{
    public static TheoryData<EdDsa, int> Keys
        => new TheoryData<EdDsa, int> { { _ed25519Key, 32 }, { _ed448Key, 57 } };
    
    private static readonly Fixture _fixture = new();
    private static readonly EdDsa _ed25519Key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);
    private static readonly EdDsa _ed448Key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed448);
    
    [Theory, MemberData(nameof(Keys))]
    public void KeySize_Expect32(EdDsa key, int expectedKeySize)
        => key.KeySize.Should().Be(expectedKeySize);
    
#pragma warning disable SYSLIB0045
    [Fact]
    public void Create_WhenEdDsaCurve_ExpectNull() 
        => System.Security.Cryptography.AsymmetricAlgorithm.Create(ExtendedSecurityAlgorithms.EdDsa).Should().BeNull();
#pragma warning restore SYSLIB0045
    
#pragma warning disable SYSLIB0007
    [Fact]
    public void Create_ExpectPlatformNotSupportedException()
        => Assert.Throws<PlatformNotSupportedException>(EdDsa.Create);
#pragma warning restore SYSLIB0007

    [Theory, MemberData(nameof(Keys))]
    public void LegalKeySizes_ExpectCorrectValues(EdDsa key, int keySize)
        => key.LegalKeySizes.Should().BeEquivalentTo(new[] { new KeySizes(keySize, keySize, 0) });

    [Theory, MemberData(nameof(Keys))]
    public void SignatureAlgorithm_ExpectEdDSA(EdDsa key, int _)
        => key.SignatureAlgorithm.Should().Be(ExtendedSecurityAlgorithms.EdDsa);
    
    [Theory, MemberData(nameof(Keys))]
    public void KeyExchangeAlgorithm_ExpectNull(EdDsa key, int _)
        => key.KeyExchangeAlgorithm.Should().BeNull();

    [Theory, MemberData(nameof(Keys))]
    public void FromXmlString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.FromXmlString(""));
    
    [Theory, MemberData(nameof(Keys))]
    public void ToXmlString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ToXmlString(true));

    [Theory, MemberData(nameof(Keys))]
    public void ImportEncryptedPkcs8PrivateKey_WithPasswordBytes_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ImportEncryptedPkcs8PrivateKey(Array.Empty<byte>(), Array.Empty<byte>(), out var _));
    
    [Theory, MemberData(nameof(Keys))]
    public void ImportEncryptedPkcs8PrivateKey_WithPasswordString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ImportEncryptedPkcs8PrivateKey(Array.Empty<char>(), Array.Empty<byte>(), out var _));
    
    [Theory, MemberData(nameof(Keys))]
    public void ImportPkcs8PrivateKey_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ImportPkcs8PrivateKey(Array.Empty<byte>(), out var _));
    
    [Theory, MemberData(nameof(Keys))]
    public void ImportSubjectPublicKeyInfo_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ImportSubjectPublicKeyInfo(Array.Empty<byte>(), out var _));

    [Theory, MemberData(nameof(Keys))]
    public void ExportEncryptedPkcs8PrivateKey_WithPasswordBytes_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ExportEncryptedPkcs8PrivateKey(Array.Empty<byte>(), _fixture.Create<PbeParameters>()));
    
    [Theory, MemberData(nameof(Keys))]
    public void ExportEncryptedPkcs8PrivateKey_WithPasswordString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ExportEncryptedPkcs8PrivateKey(Array.Empty<char>(), _fixture.Create<PbeParameters>()));
    
    [Theory, MemberData(nameof(Keys))]
    public void ExportPkcs8PrivateKey_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(key.ExportPkcs8PrivateKey);
    
    [Theory, MemberData(nameof(Keys))]
    public void ExportSubjectPublicKeyInfo_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(key.ExportSubjectPublicKeyInfo);

    [Theory, MemberData(nameof(Keys))]
    public void TryExportEncryptedPkcs8PrivateKey_WithPasswordBytes_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportEncryptedPkcs8PrivateKey(Array.Empty<byte>(), _fixture.Create<PbeParameters>(), Array.Empty<byte>(), out var _));

    [Theory, MemberData(nameof(Keys))]
    public void TryExportEncryptedPkcs8PrivateKey_WithPasswordString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportEncryptedPkcs8PrivateKey(Array.Empty<char>(), _fixture.Create<PbeParameters>(), Array.Empty<byte>(), out var _));

    [Theory, MemberData(nameof(Keys))]
    public void TryExportPkcs8PrivateKey_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportPkcs8PrivateKey(Array.Empty<byte>(), out var _));

    [Theory, MemberData(nameof(Keys))]
    public void TryExportSubjectPublicKeyInfo_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportSubjectPublicKeyInfo(Array.Empty<byte>(), out var _));
    
    [Theory, MemberData(nameof(Keys))]
    public void ImportFromEncryptedPem_WithPasswordString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ImportFromEncryptedPem(Array.Empty<char>(), Array.Empty<char>()));
    
    [Theory, MemberData(nameof(Keys))]
    public void ImportFromEncryptedPem_WithPasswordBytes_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ImportFromEncryptedPem(Array.Empty<char>(), Array.Empty<byte>()));
    
    [Theory, MemberData(nameof(Keys))]
    public void ImportFromPem_WithPasswordBytes_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ImportFromPem(Array.Empty<char>()));
    
    [Theory, MemberData(nameof(Keys))]
    public void ExportPkcs8PrivateKeyPem_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ExportPkcs8PrivateKeyPem());

    [Theory, MemberData(nameof(Keys))]
    public void ExportEncryptedPkcs8PrivateKeyPem_WithPasswordString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ExportEncryptedPkcs8PrivateKeyPem(Array.Empty<char>(), _fixture.Create<PbeParameters>()));

    [Theory, MemberData(nameof(Keys))]
    public void ExportEncryptedPkcs8PrivateKeyPem_WithPasswordBytes_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.ExportEncryptedPkcs8PrivateKeyPem(Array.Empty<byte>(), _fixture.Create<PbeParameters>()));

    [Theory, MemberData(nameof(Keys))]
    public void ExportSubjectPublicKeyInfoPem_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(key.ExportSubjectPublicKeyInfoPem);

    [Theory, MemberData(nameof(Keys))]
    public void TryExportSubjectPublicKeyInfoPem_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportSubjectPublicKeyInfoPem(Array.Empty<char>(), out var _));

    [Theory, MemberData(nameof(Keys))]
    public void TryExportPkcs8PrivateKeyPem_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportPkcs8PrivateKeyPem(Array.Empty<char>(), out var _));

    [Theory, MemberData(nameof(Keys))]
    public void TryExportEncryptedPkcs8PrivateKeyPem_WithPasswordString_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportEncryptedPkcs8PrivateKeyPem(Array.Empty<char>(), _fixture.Create<PbeParameters>(), Array.Empty<char>(), out var _));

    [Theory, MemberData(nameof(Keys))]
    public void TryExportEncryptedPkcs8PrivateKeyPem_WithPasswordBytes_ExpectNotImplementedException(EdDsa key, int _)
        => Assert.Throws<NotImplementedException>(() => key.TryExportEncryptedPkcs8PrivateKeyPem(Array.Empty<byte>(), _fixture.Create<PbeParameters>(), Array.Empty<char>(), out var _));
    
    [Theory, MemberData(nameof(Keys))]
    public void Clear_WhenDisposed_ExpectNoException(EdDsa key, int _)
        => key.Clear();
    
    [Theory, MemberData(nameof(Keys))]
    public void Dispose_WhenDisposed_ExpectNoException(EdDsa key, int _)
        => key.Dispose();
}