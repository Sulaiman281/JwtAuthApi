using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace JwtAuthApi.Configure
{
    public class JwtConfiguration
    {
        public static void ConfigureJwt(IServiceCollection services)
        {
            // Register JWT authentication
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    // Use the configured AppSettings to get JWT settings
                    var serviceProvider = services.BuildServiceProvider();
                    var appSettings = serviceProvider.GetRequiredService<IOptions<AppSettings>>().Value;
                    var jwtSettings = appSettings.JwtSettings;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero
                    };

                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            Console.WriteLine(context.Response.HasStarted + " Token validation failed: " + context.Exception.Message);
                            // context.Response.StatusCode = 401;
                            // context.Response.ContentType = "application/json";
                            // context.Response.WriteAsync(JsonConvert.SerializeObject(new { error = context.Exception.Message }));
                            // return context.Response.CompleteAsync();
                            return Task.CompletedTask;
                        },
                        OnTokenValidated = context =>
                        {
                            Console.WriteLine("Token validated successfully");
                            return Task.CompletedTask;
                        },
                        OnForbidden = context =>
                        {
                            Console.WriteLine(context.Response.HasStarted + " Forbidden: " + context.Response.StatusCode);
                            // context.Response.StatusCode = 403;
                            // context.Response.WriteAsync(JsonConvert.SerializeObject(new { error = "Forbidden" }));
                            return Task.CompletedTask;
                        },
                        OnChallenge = context =>
                        {
                            Console.WriteLine("Challenge: " + context.Response.StatusCode);
                            return Task.CompletedTask;
                        },
                        OnMessageReceived = context =>
                        {
                            Console.WriteLine("Message received: " + context.Token);
                            return Task.CompletedTask;
                        }
                    };
                });
        }
    }
}