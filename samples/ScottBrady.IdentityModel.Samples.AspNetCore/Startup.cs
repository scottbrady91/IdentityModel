using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using ScottBrady.IdentityModel.AspNetCore.Identity;

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