using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using ScottBrady.IdentityModel.AspNetCore.Identity;
using ScottBrady.IdentityModel.Tokens.Branca;
using ScottBrady.IdentityModel.Tokens.Paseto;

namespace ScottBrady.IdentityModel.Samples.AspNetCore;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        IdentityModelEventSource.ShowPII = true;
            
        services.AddControllersWithViews()
            .AddRazorRuntimeCompilation();

        var sampleOptions = new SampleOptions();
        services.AddSingleton(sampleOptions);
            
        services.AddAuthentication()
            .AddJwtBearer("branca-bearer", options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new BrancaTokenHandler());
                options.TokenValidationParameters.TokenDecryptionKey = sampleOptions.BrancaEncryptingCredentials.Key;
                options.TokenValidationParameters.ValidIssuer = "me";
                options.TokenValidationParameters.ValidAudience = "you";
            })
            .AddJwtBearer("paseto-bearer-v1", options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new PasetoTokenHandler(
                    new Dictionary<string, PasetoVersionStrategy> {{PasetoConstants.Versions.V1, new PasetoVersion1()}}));
                    
                options.TokenValidationParameters.IssuerSigningKey = sampleOptions.PasetoV1PublicKey;
                options.TokenValidationParameters.ValidIssuer = "me";
                options.TokenValidationParameters.ValidAudience = "you";
            })
            .AddJwtBearer("paseto-bearer-v2", options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new PasetoTokenHandler(
                    new Dictionary<string, PasetoVersionStrategy> {{PasetoConstants.Versions.V2, new PasetoVersion2()}}));
                    
                options.TokenValidationParameters.IssuerSigningKey = sampleOptions.EdDsaPublicKey;
                options.TokenValidationParameters.ValidIssuer = "me";
                options.TokenValidationParameters.ValidAudience = "you";
            })
            .AddJwtBearer("eddsa", options =>
            {
                options.TokenValidationParameters.IssuerSigningKey = sampleOptions.EdDsaPublicKey;
                options.TokenValidationParameters.ValidIssuer = "me";
                options.TokenValidationParameters.ValidAudience = "you";
            });

        services.AddIdentityCore<IdentityUser>(options =>
            {
                options.Password = new ExtendedPasswordOptions
                {
                    RequiredLength = 15,
                    RequireDigit = true,
                    RequireLowercase = true,
                    RequireUppercase = true,
                    RequireNonAlphanumeric = true,
                        
                    // extended options
                    MaxLength = 64,
                    MaxConsecutiveChars = 3
                };
            })
            .AddPasswordValidator<ExtendedPasswordValidator<IdentityUser>>() // Required for max length and consecutive character checks
            .AddEntityFrameworkStores<IdentityDbContext>();
            
        services.AddDbContext<IdentityDbContext>(options => options.UseInMemoryDatabase("test"));
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();

        app.UseHttpsRedirection();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
    }
}