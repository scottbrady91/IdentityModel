using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Samples.AspNetCore.Models;

namespace ScottBrady.IdentityModel.Samples.AspNetCore.Controllers;

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
    public IActionResult EdDsaJwt()
    {
        var handler = new JsonWebTokenHandler();

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            SigningCredentials = new SigningCredentials(options.EdDsaPrivateKey, ExtendedSecurityAlgorithms.EdDsa)
        };

        var token = handler.CreateToken(descriptor);
        var payloadClaims = handler.ReadJsonWebToken(token).Claims;
        
        var claimsJson = new JsonObject();
        foreach (var claim in payloadClaims)
        {
            if (claim.ValueType.Contains("integer"))
            {
                claimsJson.Add(claim.Type, int.Parse(claim.Value));
            }
            else
            {
                claimsJson.Add(claim.Type, claim.Value);
            }
        }

        return View("Index", new TokenModel
        {
            Type = "EdDSA JWT",
            Token = token,
            Payload = claimsJson.ToString()
        });
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = "eddsa")]
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