using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using Xunit;

namespace ScottBrady.IdentityModel.Tests.Extensions;

public class ExtendedJsonWebKeyConverterTests
{
    private static readonly EdDsa _ed25519Key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519);
    private static readonly EdDsa _ed448Key = EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed448);
    private readonly JsonWebKey testKey = new JsonWebKey
    {
        Kty = ExtendedSecurityAlgorithms.KeyTypes.Ecdh,
        Alg = ExtendedSecurityAlgorithms.EdDsa,
        Crv = _ed25519Key.Parameters.Curve,
        X = Base64UrlEncoder.Encode(_ed25519Key.Parameters.X),
        D = Base64UrlEncoder.Encode(_ed25519Key.Parameters.D)
    };
    
    [Theory]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed25519)]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed448)]
    public void JsonWebKeyConverter_WithPrivateKey_ConvertFromEdDsaSecurityKey(string curve)
    {
        var edDsa = EdDsa.Create(curve);
        var key = new EdDsaSecurityKey(edDsa);
        var jwk = ExtendedJsonWebKeyConverter.ConvertFromEdDsaSecurityKey(key);

        jwk.Should().NotBeNull();
        jwk.Kty.Should().Be("OKP");
        jwk.Alg.Should().Be("EdDSA");
        jwk.Crv.Should().Be(curve);
        jwk.X.Should().Be(Base64UrlEncoder.Encode(edDsa.Parameters.X));
        jwk.D.Should().Be(Base64UrlEncoder.Encode(edDsa.Parameters.D));
    }
    
    [Theory]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed25519)]
    [InlineData(ExtendedSecurityAlgorithms.Curves.Ed448)]
    public void JsonWebKeyConverter_WithOnlyPublicKey_ConvertFromEdDsaSecurityKey(string curve)
    {
        var edDsa = EdDsa.Create(curve);
        var key = new EdDsaSecurityKey(EdDsa.Create(new EdDsaParameters(curve) { X = edDsa.Parameters.X }));
        var jwk = ExtendedJsonWebKeyConverter.ConvertFromEdDsaSecurityKey(key);

        jwk.Should().NotBeNull();
        jwk.Kty.Should().Be("OKP");
        jwk.Alg.Should().Be("EdDSA");
        jwk.Crv.Should().Be(curve);
        jwk.X.Should().Be(Base64UrlEncoder.Encode(edDsa.Parameters.X));
        jwk.D.Should().BeNull();
    }
    
    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkIsNull_ReturnsFalse()
    {
        TestAndAssertFailure(null);
    }

    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkIsNotEdDsa_ReturnsFalse()
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(RSA.Create()));
        TestAndAssertFailure(jwk);
    }

    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkHasIncorrectKeyType_ReturnsFalse()
    {
        testKey.Kty = "RSA";
        TestAndAssertFailure(testKey);
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("EDDSa")]
    public void TryConvertToEdDsaSecurityKey_WhenJwkHasIncorrectAlgorithm_ReturnsFalse(string algorithm)
    {
        testKey.Kty = algorithm;
        TestAndAssertFailure(testKey);
    }

    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkHasUnsupportedCurve_ReturnsFalse()
    {
        testKey.Crv = ExtendedSecurityAlgorithms.Curves.X25519;
        TestAndAssertFailure(testKey);
    }
    
    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkIsEd25519PrivateKey_ReturnsTrueWithCorrectKey()
    {
        testKey.Crv = _ed25519Key.Parameters.Curve;
        testKey.X = Base64UrlEncoder.Encode(_ed25519Key.Parameters.X);
        testKey.D = Base64UrlEncoder.Encode(_ed25519Key.Parameters.D);
        
        var isSuccess = ExtendedJsonWebKeyConverter.TryConvertToEdDsaSecurityKey(testKey, out var key);

        isSuccess.Should().BeTrue();
        key.PrivateKeyStatus.Should().Be(PrivateKeyStatus.Exists);
        key.EdDsa.Parameters.Curve.Should().Be(_ed25519Key.Parameters.Curve);
        key.EdDsa.Parameters.X.Should().BeEquivalentTo(_ed25519Key.Parameters.X);
        key.EdDsa.Parameters.D.Should().BeEquivalentTo(_ed25519Key.Parameters.D);
    }
    
    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkIsEd25519PublicKey_ReturnsTrueWithCorrectKey()
    {
        testKey.Crv = _ed25519Key.Parameters.Curve;
        testKey.X = Base64UrlEncoder.Encode(_ed25519Key.Parameters.X);
        testKey.D = null;
        
        var isSuccess = ExtendedJsonWebKeyConverter.TryConvertToEdDsaSecurityKey(testKey, out var key);

        isSuccess.Should().BeTrue();
        key.PrivateKeyStatus.Should().Be(PrivateKeyStatus.DoesNotExist);
        key.EdDsa.Parameters.Curve.Should().Be(_ed25519Key.Parameters.Curve);
        key.EdDsa.Parameters.X.Should().BeEquivalentTo(_ed25519Key.Parameters.X);
        key.EdDsa.Parameters.D.Should().BeNull();
    }
    
    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkIsEd448PrivateKey_ReturnsTrueWithCorrectKey()
    {
        testKey.Crv = _ed448Key.Parameters.Curve;
        testKey.X = Base64UrlEncoder.Encode(_ed448Key.Parameters.X);
        testKey.D = Base64UrlEncoder.Encode(_ed448Key.Parameters.D);
        
        var isSuccess = ExtendedJsonWebKeyConverter.TryConvertToEdDsaSecurityKey(testKey, out var key);

        isSuccess.Should().BeTrue();
        key.PrivateKeyStatus.Should().Be(PrivateKeyStatus.Exists);
        key.EdDsa.Parameters.Curve.Should().Be(_ed448Key.Parameters.Curve);
        key.EdDsa.Parameters.X.Should().BeEquivalentTo(_ed448Key.Parameters.X);
        key.EdDsa.Parameters.D.Should().BeEquivalentTo(_ed448Key.Parameters.D);
    }
    
    [Fact]
    public void TryConvertToEdDsaSecurityKey_WhenJwkIsEd448PublicKey_ReturnsTrueWithCorrectKey()
    {
        testKey.Crv = _ed448Key.Parameters.Curve;
        testKey.X = Base64UrlEncoder.Encode(_ed448Key.Parameters.X);
        testKey.D = null;
        
        var isSuccess = ExtendedJsonWebKeyConverter.TryConvertToEdDsaSecurityKey(testKey, out var key);

        isSuccess.Should().BeTrue();
        key.PrivateKeyStatus.Should().Be(PrivateKeyStatus.DoesNotExist);
        key.EdDsa.Parameters.Curve.Should().Be(_ed448Key.Parameters.Curve);
        key.EdDsa.Parameters.X.Should().BeEquivalentTo(_ed448Key.Parameters.X);
        key.EdDsa.Parameters.D.Should().BeNull();
    }

    [Fact]
    public void ConvertFromEdDsaSecurityKey_TryConvertToEdDsaSecurityKey_ExpectConvertableKey()
    {
        const string jwk = "{\"kty\":\"OKP\",\"crv\": \"Ed25519\",\"alg\":\"EdDSA\",\"x\":\"60mR98SQlHUSeLeIu7TeJBTLRG10qlcDLU4AJjQdqMQ\"}";
        var jsonWebKey = new JsonWebKey(jwk);

        ExtendedJsonWebKeyConverter.TryConvertToEdDsaSecurityKey(jsonWebKey, out var edDsaKey).Should().BeTrue();
        var convertedJsonWebKey = ExtendedJsonWebKeyConverter.ConvertFromEdDsaSecurityKey(edDsaKey);

        jsonWebKey.Should().BeEquivalentTo(convertedJsonWebKey);
    }

    [Fact]
    public void ConvertFromEdDsaSecurityKey_WithRfc8037Jwk_ExpectConvertableKey()
    {
        const string jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
        var jsonWebKey = new JsonWebKey(jwk);

        ExtendedJsonWebKeyConverter.TryConvertToEdDsaSecurityKey(jsonWebKey, out var edDsaKey).Should().BeTrue();
        var convertedJsonWebKey = ExtendedJsonWebKeyConverter.ConvertFromEdDsaSecurityKey(edDsaKey);

        // RFC8037 test vectors do not include the alg parameter
        jsonWebKey.Should().BeEquivalentTo(convertedJsonWebKey, options => options.Excluding(x => x.Alg));
    }

    private static void TestAndAssertFailure(JsonWebKey jwk)
    {
        var isSuccess = ExtendedJsonWebKeyConverter.TryConvertToEdDsaSecurityKey(jwk, out var key);
        isSuccess.Should().BeFalse();
        key.Should().BeNull();
    }
}