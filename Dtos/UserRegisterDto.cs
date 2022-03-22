namespace dotnet_webapi_jwt_auth.Dtos;

public class UserRegisterDto
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}