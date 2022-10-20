using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Simple_WebAPI.Data;
using Simple_WebAPI.Models;
using Simple_WebAPI.Services.UserService;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Simple_WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class AuthController : ControllerBase
    {

        //private static ApiUser user = new ApiUser();
        private readonly IConfiguration _configuration;
        private readonly TodolistContext _context;
        private readonly IUserService _userService;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="configuration"></param>
        /// <param name="context"></param>
        public AuthController(IConfiguration configuration, TodolistContext context, IUserService userService)
        {
            _configuration = configuration;
            _context = context;
            _userService = userService; 
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = _userService.GetMyName();
            return Ok(userName);
        }
        
        // GET: api/ApiUsers/5
        /// <summary>
        /// 
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet("{id}")]
        public async Task<ActionResult<ApiUser>> GetApiUser(int id)
        {
            var apiUser = await _context.ApiUsers.FindAsync(id);

            if (apiUser == null)
            {
                return NotFound();
            }

            return apiUser;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost("register")]
        public async Task<ActionResult<ApiUser>> Register(ApiUserDTO request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            ApiUser user = new ApiUser();
            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            _context.ApiUsers.Add(user);
 
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetApiUser", new { id = user.Id }, user);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(ApiUserDTO request)
        {
            var rs = await _context.ApiUsers.ToListAsync();
            Console.WriteLine(rs);
            foreach (var i in rs)
            {
                if (request.UserName == i.UserName)
                {
                    if (!VerifyPasswordHash(request.Password, i.PasswordHash, i.PasswordSalt))
                    {
                        return BadRequest("Wrong password.");
                    }

                    string token = CreateToken(i);

                    var refreshToken = GenerateRefreshToken();
                    //SetRefreshToken(refreshToken);

                    Console.WriteLine(refreshToken.Token);

                    i.RefreshToken = refreshToken.Token;
                    i.TokenExpires = refreshToken.Expires;
                    i.TokenCreated = refreshToken.Created;

                    _context.Entry(i).State = EntityState.Modified;
                    await _context.SaveChangesAsync();

                    return Ok(token);
                }
            }
            return BadRequest("User not found.");

        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken(RefreshTokenRequest request)
        {
            var rs = await _context.ApiUsers.ToListAsync();

            foreach (var i in rs)
            {
                if (request.UserName == i.UserName)
                {
                    if (!VerifyPasswordHash(request.Password, i.PasswordHash, i.PasswordSalt))
                    {
                        return BadRequest("Wrong password.");
                    }

                    if (i.RefreshToken != request.Token)
                    {
                        return Unauthorized("Invalid Refresh Token.");
                    }
                    else if (i.TokenExpires < DateTime.Now)
                    {
                        return Unauthorized("Token expired.");
                    }

                    string newToken = CreateToken(i);

                    var newRefreshToken = GenerateRefreshToken();
                    //SetRefreshToken(newRefreshToken);

                    Console.WriteLine(newRefreshToken.Token);

                    i.RefreshToken = newRefreshToken.Token;
                    i.TokenExpires = newRefreshToken.Expires;
                    i.TokenCreated = newRefreshToken.Created;

                    _context.Entry(i).State = EntityState.Modified;
                    await _context.SaveChangesAsync();
                    return Ok(newToken);
                }
            }   
            return BadRequest("User not found.");
            
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="password"></param>
        /// <param name="passwordHash"></param>
        /// <param name="passwordSalt"></param>
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateToken(ApiUser user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("Jwt:Key").Value));


            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: creds);

            Console.WriteLine(token);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddMinutes(30),
                Created = DateTime.Now
            };

            return refreshToken;
        }

        //private void SetRefreshToken(RefreshToken newRefreshToken)
        //{
        //    var cookieOptions = new CookieOptions
        //    {
        //        HttpOnly = true,
        //        Expires = newRefreshToken.Expires
        //    };
        //    Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

        //    //ApiUser user = new ApiUser();
        //    //user.RefreshToken = newRefreshToken.Token;
        //    //user.TokenCreated = newRefreshToken.Created;
        //    //user.TokenExpires = newRefreshToken.Expires;
        //}
    }
}