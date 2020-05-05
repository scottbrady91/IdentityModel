using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Converters;
using ScottBrady.IdentityModel.Tokens;
using SecurityAlgorithms = ScottBrady.IdentityModel.Crypto.SecurityAlgorithms;

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
        public IActionResult Paseto()
        {
            var handler = new PasetoTokenHandler();

            var descriptor = new PasetoSecurityTokenDescriptor(PasetoConstants.Versions.V2, PasetoConstants.Purposes.Public)
            {
                Issuer = "me",
                Audience = "you",
                SigningCredentials = new SigningCredentials(options.PasetoV2PrivateKey, SecurityAlgorithms.EdDSA)
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
        [Authorize(AuthenticationSchemes = "branca-bearer,paseto-bearer")]
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
