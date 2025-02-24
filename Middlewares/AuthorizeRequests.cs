using System.Net;
using Newtonsoft.Json;

namespace Middlewares
{
    public class AuthorizeRequests(RequestDelegate next)
    {
        private readonly RequestDelegate _next = next;
        public async Task Invoke(HttpContext context)
        {
            try
            {
                // log context user
                if (context.User?.Identity?.IsAuthenticated == true)
                {
                    Console.WriteLine($"User: {JsonConvert.SerializeObject(context.User.Claims.Select(x => new { x.Type, x.Value }))}");
                }
                else
                {
                    Console.WriteLine("User: Anonymous");
                }

                await _next(context);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(new { error = ex.Message }));
            }
            finally
            {
                Console.WriteLine($"Request {context.Request.Path} {context.Response.StatusCode}");
            }
        }
    }
}