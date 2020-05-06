# ScottBrady.IdentityModel

Helper libraries for tokens and cryptography in .NET.

- Branca tokens with JWT style validation
- PASETO (v2.public) with JWT style validation
- Base62 encoding
- XChaCha20-Poly1305 engine for Bouncy Castle
- [Samples](https://github.com/scottbrady91/IdentityModel/tree/master/samples/ScottBrady.IdentityModel.Samples.AspNetCore) in ASP.NET Core

**Feature requests welcome.**

## Branca Tokens

[Branca](https://branca.io/) is token construct suitable for internal systems. The payload is encrypted using XChaCha20-Poly1305. Must use a 32-byte symmetric key.

```csharp
var handler = new BrancaTokenHandler();
var key = Encoding.UTF8.GetBytes("supersecretkeyyoushouldnotcommit");

string token = handler.CreateToken(new SecurityTokenDescriptor
{
    Issuer = "me",
    Audience = "you",
    Expires = DateTime.UtcNow.AddMinutes(5),
    NotBefore = DateTime.UtcNow,
    Claims = new Dictionary<string, object> {{"sub", "123"}},
    EncryptingCredentials = new EncryptingCredentials(
        new SymmetricSecurityKey(key), SecurityAlgorithms.XChaCha20Poly1305)
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

## PASETO

[PASETO](https://paseto.io/) is a competing standard to JOSE & JWT that offers a versioned ciphersuite. This library currently implements `v2` for the `public` purpose, suitable for zero-trust systems such as an OAuth authorization server.

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
        new EdDsaSecurityKey(new Ed25519PrivateKeyParameters(privateKey, 0)), SecurityAlgorithms.EdDsa)
});

ClaimsPrincipal principal = handler.ValidateToken(
    token,
    new TokenValidationParameters
    {
        ValidIssuer = "me",
        ValidAudience = "you",
        IssuerSigningKey = new EdDsaSecurityKey(new Ed25519PublicKeyParameters(publicKey, 0))
    }, out SecurityToken parsedToken);
```

## API Protection with JWT Style Handler

The Branca and PASETO token handlers can be used with the ASP.NET Core JWT bearer authentication handler.

```csharp
services.AddAuthentication()
    .AddJwtBearer("paseto", options =>
    {
        options.SecurityTokenValidators.Clear();
        options.SecurityTokenValidators.Add(new PasetoTokenHandler());
        options.TokenValidationParameters.IssuerSigningKey = new EdDsaSecurityKey(new Ed25519PublicKeyParameters(<your_public_key>, 0));
        options.TokenValidationParameters.ValidIssuer = "you";
        options.TokenValidationParameters.ValidAudience = "me";
    })
```

## Base62 Encoding

Base62 encoding uses the `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` character set.

```csharp
var plaintext = "hello world"; // encoded = AAwf93rvy4aWQVw
var encoded = Base62.Encode(Encoding.UTF8.GetBytes(plaintext));
```
