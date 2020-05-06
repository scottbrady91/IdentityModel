# ScottBrady.IdentityModel

Helper libraries for tokens and cryptography in .NET.

Includes:
- Branca tokens with JWT style validation
- PASETO (v2.public) with JWT style validation
- Base62 encoding
- XChaCha20-Poly1305 engine for Bouncy Castle
- [Samples](https://github.com/scottbrady91/IdentityModel/tree/master/samples/ScottBrady.IdentityModel.Samples.AspNetCore) in ASP.NET Core

**Feature requests welcome.**

## Branca Tokens
A token construct suitable for internal systems. The payload is encrypted using XChaCha20-Poly1305. Must use a 32-byte symmetric key.

```
CreateToken & ValidateToken
```

## PASETO (v2.public)
PASETO is a competing standard to JOSE & JWT, offering a versioned ciphersuite. This library currently implements `v2` for the `public` purpose, suitable for zero-trust systems such as an OAuth authorization server.

```
CreateToken & ValidateToken
```

## Base62 Encoding
Base62 encoding uses the `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` character set.

```
var plaintext = "hello world"; // encoded = AAwf93rvy4aWQVw
var encoded = Base62.Encode(Encoding.UTF8.GetBytes(plaintext));
```
