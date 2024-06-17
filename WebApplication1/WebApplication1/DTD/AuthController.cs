using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebApplication1.DTD;

namespace WebApplication1.DTD;

[ApiController]
[Route("api/auth")]
public class AuthController : Controller
{
    /*
     * 
     */

    private Claim[] userClaims =
    {
        new Claim(ClaimTypes.NameIdentifier, "1"),
        new Claim(ClaimTypes.Email, "jd@pja.edu.pl")
    };

    string secret = "hjsdbjk;wehufsduhufhwuighrhguiehgurehgi";
    
    SymmetricSecurityKey = key = new (Encoding.UTF8.GetBytes);
    private SigningCredentials signingCredentials = new(key, SecurityAlgor);
    
    string 
}