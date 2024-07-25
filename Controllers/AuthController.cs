using JwtAuthenticationLearning.Core.DTOs;
using JwtAuthenticationLearning.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthenticationLearning.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        //role for seeding to db
        [HttpPost("/seedRole")]
        public async Task<ActionResult> SeedRoles()
        {
            bool isUserExist = await _roleManager.RoleExistsAsync(StaticUserRole.USER);
            bool isAdminExist = await _roleManager.RoleExistsAsync(StaticUserRole.ADMIN);
            bool isOwnerExist = await _roleManager.RoleExistsAsync(StaticUserRole.OWNER);
            
            if(isUserExist && isAdminExist && isOwnerExist)
            {
                return Ok("Role seeding already done!");
            }
            
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRole.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRole.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRole.ADMIN));

            return Ok("Role seeding successful");
        }


        //signup
        [HttpPost("/signup")]
        public async Task<ActionResult> Register([FromBody]RegisterDTO registerDTO)
        {
            var isExistUser = await _userManager.FindByNameAsync(registerDTO.UserName);


            if(isExistUser != null)
            {
                return BadRequest("User Name already exist");
            }

            IdentityUser newUser = new IdentityUser
            {
                Email = registerDTO.Email,
                UserName = registerDTO.UserName,
                SecurityStamp = new Guid().ToString()
            };

            var createUserResult = await _userManager.CreateAsync(newUser,registerDTO.Password);

            if(!createUserResult.Succeeded)
            {
                StringBuilder sb = new StringBuilder();

                foreach (var error in createUserResult.Errors)
                {
                    sb.AppendLine(error.Description);
                }
                return BadRequest(sb.ToString());
            }

            //add a default user role to all the user
            await _userManager.AddToRoleAsync(newUser, StaticUserRole.USER);
            return Ok("user is created successfully");
        }


        //login
        [HttpPost("/login")]
        public async Task<ActionResult>Login([FromBody] LoginDTO loginDTO)
        {
            var user = await _userManager.FindByNameAsync(loginDTO.UserName);

            if (user == null)
            {
                return Unauthorized("Invalid credential");
            }

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user,loginDTO.Password);

            if (!isPasswordCorrect)
            {
                return Unauthorized("Invalid credential");
            }


            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,user.UserName),
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim("JWTID",Guid.NewGuid().ToString())
            };


            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }


            var token = GenerateNewJsonWebToken(authClaims);

            return Ok(token);
        }

        private string GenerateNewJsonWebToken(List<Claim> authClaims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));

            var tokenObject = new JwtSecurityToken
                (
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddMinutes(10),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }


        //make user -> admin
        [HttpPost("make-admin")]
        public async Task<ActionResult> MakeAdmin([FromBody]UpdatePermissionDTO updatePermissionDTO)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);

            if (user == null)
            {
                return BadRequest("Invalid User Name");
            }

            await _userManager.AddToRoleAsync(user, StaticUserRole.ADMIN);
            return Ok("User is now admin");
        }

        //make user -> owner
        [HttpPost("make-owner")]
        public async Task<ActionResult> MakeOwner([FromBody] UpdatePermissionDTO updatePermissionDTO)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);

            if (user == null)
            {
                return BadRequest("Invalid User Name");
            }

            await _userManager.AddToRoleAsync(user, StaticUserRole.OWNER);
            return Ok("User is now owner");
        }

    }
}
