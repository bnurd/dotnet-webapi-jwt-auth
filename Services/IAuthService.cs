using dotnet_webapi_jwt_auth;
using dotnet_webapi_jwt_auth.Dtos;
using dotnet_webapi_jwt_auth.Models;
using dotnet_webapi_jwt_auth.Utils;

namespace dotnet_webapi_jwt_auth.Services;

public interface IAuthService
{
    dotnet_webapi_jwt_auth.IResult Register(UserRegisterDto userRegisterDto);
    IDataResult<string> Login(UserLoginDto userLoginDto);
}

class AuthManager : IAuthService
{
    static User user = new User();

    IPasswordCryptionService _passwordCryptionService;
    ITokenService _tokenService;

    public AuthManager(IPasswordCryptionService passwordCryptionService, ITokenService tokenService)
    {
        _passwordCryptionService = passwordCryptionService;
        _tokenService = tokenService;
    }

    public IDataResult<string> Login(UserLoginDto userLoginDto)
    {
        try
        {
            if (user.Username != userLoginDto.Username)
            {
                return new ErrorDataResult<string>(message: "The user is not exists");
            }

            if (!_passwordCryptionService.ValidatePassword(userLoginDto.Password, user.PasswordSalt, user.PasswordHash))
            {
                return new ErrorDataResult<string>(message: "Password is not valid");
            }

            var token = _tokenService.GenerateJwtToken(user);
            return new SuccessDataResult<string>(data: token);
        }
        catch (System.Exception ex)
        {
            return new ErrorDataResult<string>(message: ex.Message);
        }
    }

    public dotnet_webapi_jwt_auth.IResult Register(UserRegisterDto userRegisterDto)
    {
        try
        {
            user.Username = userRegisterDto.Username;
            _passwordCryptionService.GeneratePassword(userRegisterDto.Password, out byte[] passwordSalt, out byte[] passwordHash);

            user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;

            return new SuccessResult();
        }
        catch (System.Exception ex)
        {
            return new ErrorResult(ex.Message);
        }
    }
}