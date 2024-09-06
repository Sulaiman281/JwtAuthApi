using Newtonsoft.Json;

namespace Middlewares
{
    public class AuthorizeRequests(RequestDelegate next)
    {
        private readonly RequestDelegate _next = next;
        public async Task Invoke(HttpContext context)
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
    }
}