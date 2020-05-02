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
                    options.SecurityTokenValidators.Add(new BrancaTokenHandler());
                    options.TokenValidationParameters.TokenDecryptionKey = sampleOptions.EncryptingCredentials.Key;
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
