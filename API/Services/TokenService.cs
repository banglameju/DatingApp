using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
        }

        public string CreateToken(AppUser user)
        {
            //claims will be used in token descriptor
            var claims = new List<Claim>
            {
               new Claim(JwtRegisteredClaimNames.NameId, user.UserName) 
            };

            //creds will be used in token descriptor
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            //token descriptor willbe used to create token by token handler
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds
            };

            //token handler will create token using token descriptor
            //and will be used to write token to return back
             var tokenHandler = new JwtSecurityTokenHandler();

            //token will be written with token handler to return back
             var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);     
        }
    }
}