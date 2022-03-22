using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using dotnet_webapi_jwt_auth.Models;
using Microsoft.IdentityModel.Tokens;

namespace dotnet_webapi_jwt_auth.Utils;

public interface ITokenService
{
    string GenerateJwtToken(User user);
}

public class TokenService : ITokenService
{
    private DateTime ExpireTime { get; set; } = DateTime.Now.AddDays(1);

    IConfiguration _configuration;

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string GenerateJwtToken(User user)
    {
        List<Claim> claims = new List<Claim> {
            new Claim(ClaimTypes.Name , user.Username),
            new Claim(ClaimTypes.Role , "Admin")
        };

        var secret = _configuration.GetSection("AppSettings:Token").Value;
        var encodedSecret = System.Text.Encoding.UTF8.GetBytes(secret);
        var key = new SymmetricSecurityKey(encodedSecret);
        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: ExpireTime,
            signingCredentials: cred
        );

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return jwt;
    }
}