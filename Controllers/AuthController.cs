using Microsoft.AspNetCore.Mvc;
using Models;
using Services;

namespace Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController(IUserService userService) : ControllerBase
    {
        private readonly IUserService _userService = userService;

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            return Ok(await _userService.Authenticate(request));
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            return Ok(await _userService.Register(request));
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromForm] string accessToken, [FromForm] string refreshToken)
        {
            return Ok(await _userService.RefreshToken(accessToken, refreshToken));
        }
    }
}