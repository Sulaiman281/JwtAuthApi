namespace JwtAuthApi.Configure
{
    public class AuthorizationConfig
    {
        public static void ConfigureAuthorization(IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
                options.AddPolicy("User", policy => policy.RequireRole("User"));
                options.AddPolicy("AdminOrUser", policy => policy.RequireRole("Admin", "User"));
            });
        }
    }
}
