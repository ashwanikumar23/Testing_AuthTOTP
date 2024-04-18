using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using static Testing_AuthTOTP.Models.AuthModel;

namespace Testing_AuthTOTP.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class TestsController : ControllerBase
    {
        [HttpGet]
        public string Get()
        {
            return "This controller is accessable ";
        }
    }
}
