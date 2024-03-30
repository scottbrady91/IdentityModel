# ScottBrady.IdentityModel

[![NuGet](https://img.shields.io/nuget/v/ScottBrady.IdentityModel.svg)](https://www.nuget.org/packages/ScottBrady.IdentityModel/)

Helper libraries for tokens and cryptography in .NET.

- EdDSA support for JWTs (Ed25519 and Ed448)
- Base16 (hex) and Base62 encoders
- `passwordrule` attribute support for ASP.NET Identity
- [Samples](https://github.com/scottbrady91/IdentityModel/tree/master/samples/ScottBrady.IdentityModel.Samples.AspNetCore) in ASP.NET Core
- ~~Branca tokens with JWT style validation~~ (deprecated due to low usage of Branca)
- ~~PASETO (v1.public & v2.public) with JWT style validation~~ (deprecated due to low usage of PASETO)

**Feature requests welcome. Please see SECURITY.md for responsible disclosure policy.**

## EdDSA support

EdDSA is a modern signing algorithm that is not yet supported out of the box in .NET.
This library provides some useful abstractions around the Bouncy Castle (software) implementation of EdDSA.

```csharp
// create EdDSA new key pair
EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519)

// create EdDSA key from parameters
EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) 
  {D = Base64UrlEncoder.DecodeBytes(privateKey)})

// create EdDSA security key for use with Microsoft.IdentityModel JWT APIs (alg: EdDSA)
new EdDsaSecurityKey(EdDsa.Create(ExtendedSecurityAlgorithms.Curves.Ed25519))
```

## Base16 (hex) Encoding

Base16 allows you to encode and decode hexadecimal strings.

```csharp
var plaintext = "hello world"; // encoded = 68656c6c6f20776f726c64
string encoded = Base16.Encode(Encoding.UTF8.GetBytes(plaintext));
```

## Base62 Encoding

Base62 encoding uses the `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` character set.

```csharp
var plaintext = "hello world"; // encoded = AAwf93rvy4aWQVw
string encoded = Base62.Encode(Encoding.UTF8.GetBytes(plaintext));
```

## JWT alternatives (deprecated)

### Branca Tokens

[Branca](https://branca.io/) is a token construct suitable for internal systems.
The payload is encrypted using XChaCha20-Poly1305, using a 32-byte symmetric key.

This library supports the creation of Branca tokens with an arbitrary payload or using a JWT-style payload.

- NuGet: [ScottBrady.IdentityModel.Tokens.Branca](https://www.nuget.org/packages/ScottBrady.IdentityModel.Tokens.Branca)
- [Test vectors](https://github.com/scottbrady91/IdentityModel/tree/master/test/ScottBrady.IdentityModel.Tests/Tokens/Branca/TestVectors)

```csharp
var handler = new BrancaTokenHandler();
var key = Encoding.UTF8.GetBytes("supersecretkeyyoushouldnotcommit");

// JWT-style payload
string token = handler.CreateToken(new SecurityTokenDescriptor
{
    Issuer = "me",
    Audience = "you",
    Expires = DateTime.UtcNow.AddMinutes(5),
    NotBefore = DateTime.UtcNow,
    Claims = new Dictionary<string, object> {{"sub", "123"}},
    EncryptingCredentials = new EncryptingCredentials(
        new SymmetricSecurityKey(key), ExtendedSecurityAlgorithms.XChaCha20Poly1305)
});

ClaimsPrincipal principal = handler.ValidateToken(
    token,
    new TokenValidationParameters
    {
        ValidIssuer = "me",
        ValidAudience = "you",
        TokenDecryptionKey = new SymmetricSecurityKey(key)
    }, out SecurityToken parsedToken);
```

> [!IMPORTANT]
> Branca support is now deprecated and only supports Microsoft.IdentityModel 6.35.0.
> This is due to the low usage of this library and the Branca project as a whole.

### PASETO

[PASETO](https://paseto.io/) is a competing standard to JOSE & JWT that offers a versioned ciphersuite.
This library currently implements `v1` and `v2` for the `public` purpose, suitable for zero-trust systems such as an OAuth authorization server.

Explicit versioning allows PASETO to side-step [attacks on signature validation](https://www.rfc-editor.org/rfc/rfc8725.html#name-weak-signatures-and-insuffi) found in some JWT libraries.
However, it does not mitigate any other attacks.

If you are considering using PASETO, I recommend reading [RFC 8725 - JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html) and deciding if the interoperable JWT format is still wrong for you.

- NuGet: [ScottBrady.IdentityModel.Tokens.Paseto](https://www.nuget.org/packages/ScottBrady.IdentityModel.Tokens.Paseto)
- [Test vectors](https://github.com/scottbrady91/IdentityModel/tree/master/test/ScottBrady.IdentityModel.Tests/Tokens/Paseto/TestVectors)

```csharp
var handler = new PasetoTokenHandler();
var privateKey = Convert.FromBase64String("TYXei5+8Qd2ZqKIlEuJJ3S50WYuocFTrqK+3/gHVH9B2hpLtAgscF2c9QuWCzV9fQxal3XBqTXivXJPpp79vgw==");
var publicKey = Convert.FromBase64String("doaS7QILHBdnPULlgs1fX0MWpd1wak14r1yT6ae/b4M=");

string token = handler.CreateToken(new PasetoSecurityTokenDescriptor(
    PasetoConstants.Versions.V2, PasetoConstants.Purposes.Public)
{
    Issuer = "me",
    Audience = "you",
    Expires = DateTime.UtcNow.AddMinutes(5),
    NotBefore = DateTime.UtcNow,
    Claims = new Dictionary<string, object> {{"sub", "123"}},
    SigningCredentials = new SigningCredentials(
        new EdDsaSecurityKey(EdDsa.Create(
            new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519)
            {
                D = privateKey
            })), ExtendedSecurityAlgorithms.EdDsa)
});

ClaimsPrincipal principal = handler.ValidateToken(
    token,
    new TokenValidationParameters
    {
        ValidIssuer = "me",
        ValidAudience = "you",
        IssuerSigningKey = new EdDsaSecurityKey(EdDsa.Create(
            new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) {X = publicKey}))
    }, out SecurityToken parsedToken);
```

> [!IMPORTANT]
> PASETO support is now deprecated and only supports Microsoft.IdentityModel 6.35.0.
> This is due to the low usage of this library and the PASETO project as a whole.

### API Protection with JWT Style Handler

The Branca and PASETO token handlers can be used with the ASP.NET Core JWT bearer authentication handler.

```csharp
services.AddAuthentication()
    .AddJwtBearer("paseto", options =>
    {
        options.SecurityTokenValidators.Clear();
        options.SecurityTokenValidators.Add(new PasetoTokenHandler());
        options.TokenValidationParameters.IssuerSigningKey = new EdDsaSecurityKey(EdDSA.Create(<your_public_key>));
        options.TokenValidationParameters.ValidIssuer = "you";
        options.TokenValidationParameters.ValidAudience = "me";
    })
```
