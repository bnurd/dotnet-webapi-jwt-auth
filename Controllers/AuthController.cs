using dotnet_webapi_jwt_auth.Dtos;
using dotnet_webapi_jwt_auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace dotnet_webapi_jwt_auth.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IAuthService _authService;
    private readonly IUserService _userService;

    public AuthController(ILogger<AuthController> logger, IAuthService authService, IUserService userService)
    {
        _logger = logger;
        _authService = authService;
        _userService = userService;
    }


    [HttpGet("GetMe"), Authorize]
    public ActionResult<object> GetMe()
    {
        var result = _userService.GetMe();
        return Ok(result);
        /* var userName = User?.Identity?.Name;
        var userName2 = User.FindFirstValue(ClaimTypes.Name);
        var role = User.FindFirstValue(ClaimTypes.Role);

        return Ok(new
        {
            userName,
            userName2,
            role
        }); */
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(UserRegisterDto userRegisterDto)
    {
        var result = _authService.Register(userRegisterDto);
        if (result.Success) return Ok(result);
        else return BadRequest(result.Message);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(UserLoginDto userLoginDto)
    {
        var result = _authService.Login(userLoginDto);
        if (result.Success) return Ok(result);
        else return BadRequest(result.Message);
    }

}