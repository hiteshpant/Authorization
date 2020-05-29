using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthorizationController : ControllerBase
    {
        public static IList<AuthModel> AvailableAuthModels = GetAvailableAuthModels();
        private IConfiguration _Config;

        public AuthorizationController(IConfiguration config)
        {
            _Config = config;
        }

        [HttpGet]
        [Authorize]
        public ActionResult<IEnumerable<string>> Get()
        {
            return Ok(GetAvailableAuthModels());
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("GetToken")]
        public IActionResult GetToken()
        {
            IActionResult response = Unauthorized();

            //ideally if user exist in db then ob
            //IActionResult response = Unauthorized();
            //var user = AuthenticateUser(login);

            //if (user != null)
            //{
            //    var tokenString = GenerateJSONWebToken(user);
            //    response = Ok(new { token = tokenString });
            //}
            var tokenString = GenerateJSONWebToken("AuthDemo","myaauthdemo");
            response = Ok(new { token = tokenString });
            return response;
        }

        private string GenerateJSONWebToken(string username,string password)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_Config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_Config["Jwt:Issuer"],
              _Config["Jwt:Issuer"],
              null,
              expires: DateTime.Now.AddMinutes(120),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost]
        [Authorize]
        public ActionResult Post(AuthModel model)
        {
            if (AvailableAuthModels.FirstOrDefault(x => x.Term == model.Term) == null)
            {
                AvailableAuthModels.Add(model);
                var resourceUrl = Path.Combine(Request.Path.ToString(), Uri.EscapeUriString(model.Term));
                return Created(resourceUrl, model);
            }
            else
            {
                return Conflict("Cannot create sae Term it already exists");
            }
        }

        [HttpDelete]
        [Route("{term}")]
        [Authorize]
        public ActionResult Delete(string term)
        {
            var tobeDeletedItem = AvailableAuthModels.FirstOrDefault(x => x.Term == term);
            if (tobeDeletedItem != null)
            {
                AvailableAuthModels.Remove(tobeDeletedItem);
                return NoContent();
            }
            else
            {
                return NotFound();
            }
        }

        private static IList<AuthModel> GetAvailableAuthModels()
        {
            return new List<AuthModel>
            {
             new AuthModel
             {
                 Term = "Access Token",
                 Definition = "A credential that can be used by an application to access an API. It informs the API that the bearer of the token has been authorized to access the API and perform specific actions specified by the scope that has been granted."
             },
            new AuthModel
            {
                Term = "JWT",
                Definition = "An open, industry standard RFC 7519 method for representing claims securely between two parties. "
            },
            new AuthModel
            {
                Term = "OpenID",
                Definition = "An open standard for authentication that allows applications to verify users are who they say they are without needing to collect, store, and therefore become liable for a user’s login information."
            }};
        }
    }

}

