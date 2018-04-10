using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace iTrade.API.Controllers
{
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        // GET api/values
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }
        
        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("protected")]
        public IEnumerable<string> Protected()
        {
            return new string[] { "Access granted as you are a logged in user !" };
        }

        [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin, ADMIN")]
        [HttpGet("admin-protected")]
        public IEnumerable<string> AdminProtected()
        {
            return new string[] { "Access granted as you are an admin !" };
        }
    }
}
