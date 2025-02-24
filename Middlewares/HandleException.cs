using System.Net;
using Newtonsoft.Json;
using Services;

namespace JwtAuthApi.Middlewares
{
    public class HandleException(RequestDelegate next, ILogger<HandleException> logger)
    {
        private readonly RequestDelegate _next = next;
        private readonly ILogger<HandleException> _logger = logger;

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine("Argument Exception: " + ex.Message);
                _logger.LogError(ex, ex.Message);
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(new { error = ex.Message }));
            }
            catch (TokenException ex)
            {
                Console.WriteLine("Token Exception: " + ex.Message);
                _logger.LogError(ex, ex.Message);
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(new { error = ex.Message }));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
                _logger.LogError(ex, ex.Message);
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(new { error = ex.Message }));
            }
            finally
            {
                _logger.LogInformation($"Request {context.Request.Path} {context.Response.StatusCode}");
            }
        }
    }
}