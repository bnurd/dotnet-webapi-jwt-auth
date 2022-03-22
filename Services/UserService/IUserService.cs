using System.Security.Claims;

namespace dotnet_webapi_jwt_auth.Services.UserService;

public interface IUserService
{
    object GetMe();
}

public class UserManager : IUserService
{
    private readonly IHttpContextAccessor _accessor;

    public UserManager(IHttpContextAccessor accessor)
    {
        _accessor = accessor;
    }


    public object GetMe()
    {
        if (_accessor.HttpContext != null)
        {
            var userName = _accessor.HttpContext?.User.FindFirstValue(ClaimTypes.Name);
            var role = _accessor.HttpContext?.User.FindFirstValue(ClaimTypes.Role);
            return new
            {
                userName,
                role
            };
        }
        return new { };
    }
}