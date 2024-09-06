using Entity;
using JwtAuthApi.Configure;
using JwtAuthApi.Middlewares;
using Middlewares;
using Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));
builder.Services.AddSingleton<JwtService>();


JwtConfiguration.ConfigureJwt(builder.Services);
builder.Services.AddAuthorization();

builder.Services.AddSingleton<UserRepository>(); // temp database for testing
builder.Services.AddScoped<IUserService, UserService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseMiddleware<AuthorizeRequests>();
app.UseMiddleware<HandleException>();

app.MapGet("/", () => "Hello World!");

app.MapControllers();

app.Run();