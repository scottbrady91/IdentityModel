using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Samples.AspNetCore.Controllers
{
    public class HomeController : Controller
    {
        private readonly SampleOptions options;

        public HomeController(SampleOptions options)
        {
            this.options = options ?? throw new ArgumentNullException(nameof(options));
        }
        
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Branca()
        {
            var handler = new BrancaTokenHandler();

            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
               Issuer = "me",
               Audience = "you",
               EncryptingCredentials = options.BrancaEncryptingCredentials
            });

            var parsedToken = handler.DecryptToken(token, ((SymmetricSecurityKey) options.BrancaEncryptingCredentials.Key).Key);

            return View("Index", new TokenModel
            {
                Type = "Branca",
                Token = token,
                Payload = parsedToken.Payload
            });
        }

        [HttpGet]
        public IActionResult Paseto(string version)
        {
            var handler = new PasetoTokenHandler();

            SigningCredentials signingCredentials;
            if (version == PasetoConstants.Versions.V1)
                signingCredentials = new SigningCredentials(options.PasetoV1PrivateKey, SecurityAlgorithms.RsaSsaPssSha384);
            else if (version == PasetoConstants.Versions.V2)
                signingCredentials = new SigningCredentials(options.PasetoV2PrivateKey, ExtendedSecurityAlgorithms.EdDsa);
            else 
                throw new NotSupportedException("Unsupported version");
            
            var descriptor = new PasetoSecurityTokenDescriptor(version, PasetoConstants.Purposes.Public)
            {
                Issuer = "me",
                Audience = "you",
                SigningCredentials = signingCredentials
            };

            var token = handler.CreateToken(descriptor);
            var payload = descriptor.ToJwtPayload(JwtDateTimeFormat.Iso);

            return View("Index", new TokenModel
            {
                Type = "PASETO",
                Token = token,
                Payload = payload
            });
        }
        
        [HttpGet]
        public IActionResult EdDsaJwt()
        {
            var handler = new JsonWebTokenHandler();

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                SigningCredentials = new SigningCredentials(options.PasetoV2PrivateKey, ExtendedSecurityAlgorithms.EdDsa)
            };

            var token = handler.CreateToken(descriptor);
            var payload = descriptor.ToJwtPayload(JwtDateTimeFormat.Iso);

            return View("Index", new TokenModel
            {
                Type = "EdDSA JWT",
                Token = token,
                Payload = payload
            });
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = "branca-bearer,paseto-bearer-v1,paseto-bearer-v2,eddsa")]
        public IActionResult CallApi()
        {
            return Ok();
        }
    }

    public class TokenModel
    {
        public string Type { get; set; }
        public string Token { get; set; }
        public string Payload { get; set; }
    }
}
