using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using ScottBrady.IdentityModel.Tokens;

namespace ScottBrady.IdentityModel.Samples.AspNetCore
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
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
                    options.SecurityTokenValidators.Add(new PasetoTokenHandler());
                    options.TokenValidationParameters.IssuerSigningKey = sampleOptions.PasetoV1PublicKey;
                    options.TokenValidationParameters.ValidIssuer = "me";
                    options.TokenValidationParameters.ValidAudience = "you";
                })
                .AddJwtBearer("paseto-bearer-v2", options =>
                {
                    options.SecurityTokenValidators.Clear();
                    options.SecurityTokenValidators.Add(new PasetoTokenHandler());
                    options.TokenValidationParameters.IssuerSigningKey = sampleOptions.PasetoV2PublicKey;
                    options.TokenValidationParameters.ValidIssuer = "me";
                    options.TokenValidationParameters.ValidAudience = "you";
                });
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
}
