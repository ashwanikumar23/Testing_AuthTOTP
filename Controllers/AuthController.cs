using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Testing_AuthTOTP.Models;
using QRCoder;
using System.Drawing;
using System.IO;
using static Testing_AuthTOTP.Models.AuthModel;
using static System.Net.Mime.MediaTypeNames;

namespace Testing_AuthTOTP.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthModel _auth;

        public AuthController(IAuthModel auth)
        {
            _auth = auth;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(LoginUser? pUser)
        {
            var userName = pUser.UserName.ToLower();
            if (await _auth.UserExists(userName))
                return BadRequest("User already exist!");

            var user = await _auth.RegisterUser(pUser);
            return user?StatusCode(201): BadRequest("Error... !"); 
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginUser? pUser)
        {
            var userName = pUser?.UserName?.ToLower();
            var user = await _auth.Login(pUser);
            if (user)
            {
                var token = await _auth.GenerateWebToken(pUser);
                return Ok(token);
            }
            return  BadRequest("Error... !");
        }

        [HttpPost("getQRCode")]
        public async Task<IActionResult> GetQRCode(LoginUser pUser)
        {
            if (pUser.UserName != null)
            {
                var token = await _auth.OnGetAsync(pUser);
                using (var qrGenerator = new QRCodeGenerator())
                {
                    var qrCodeData = qrGenerator.CreateQrCode(token, QRCodeGenerator.ECCLevel.Q);
                   
                    var qrCode = new QRCode(qrCodeData);
                    using (var qrCodeImage = qrCode.GetGraphic(60))
                    {
                        using (var stream = new MemoryStream())
                        {
                            qrCodeImage.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
                            stream.Position = 0;
                            return File(stream.ToArray(), "image/png");
                        }
                    }
                }
               // return Ok(token);
            }
            return BadRequest("Error... !");
        }

        [HttpPost("Varify-Code")]
        public async Task<IActionResult> VarifyQRCode(LoginUser pUser,string code)
        {
            if (await _auth.OnVarifyAsync(pUser, code))
            {
                var token = await _auth.GenerateWebToken(pUser);
                //var res = { Status:"ok ",message: " Successfully varify",token: token}
            return Ok(" Successfully varify \n,"+ token);
            }
            return BadRequest("Error... !");

        }

    }
}
