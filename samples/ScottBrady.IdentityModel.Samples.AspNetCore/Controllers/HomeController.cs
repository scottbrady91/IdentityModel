using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Samples.AspNetCore.Models;
using ScottBrady.IdentityModel.Tokens;
using BrancaTokenHandler = ScottBrady.IdentityModel.Tokens.Branca.BrancaTokenHandler;

namespace ScottBrady.IdentityModel.Samples.AspNetCore.Controllers
{
    public class HomeController : Controller
    {
        private readonly SampleOptions options;
        private readonly UserManager<IdentityUser> userManager;

        public HomeController(SampleOptions options, UserManager<IdentityUser> userManager)
        {
            this.options = options ?? throw new ArgumentNullException(nameof(options));
            this.userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
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

        [HttpGet]
        public IActionResult PasswordRules()
        {
            return View(new PasswordRulesModel());
        }

        [HttpPost]
        public async Task<IActionResult> PasswordRules(PasswordRulesModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var errors = new List<string>();
            foreach (var validator in userManager.PasswordValidators)
            {
                var result = await validator.ValidateAsync(userManager, new IdentityUser(), model.Password);
                if (!result.Succeeded)
                {
                    if (result.Errors.Any())
                    {
                        errors.AddRange(result.Errors.Select(x => x.Description));
                    }
                }
            }

            model.Errors = errors;
            model.Message = errors.Any() ? "Password failed server-side validation" : "Password passed server-side validation";
            return View(model);
        }
    }
}
