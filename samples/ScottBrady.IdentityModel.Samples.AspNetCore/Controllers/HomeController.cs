using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
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

        public IActionResult Branca()
        {
            var handler = new BrancaTokenHandler();

            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
               Issuer = "me",
               Audience = "you",
               EncryptingCredentials = options.EncryptingCredentials
            });

            var parsedToken = handler.DecryptToken(token, ((SymmetricSecurityKey) options.EncryptingCredentials.Key).Key);

            return View("Index", new TokenModel
            {
                Type = "Branca",
                Token = token,
                Payload = parsedToken.Payload
            });
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = "branca-bearer")]
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
