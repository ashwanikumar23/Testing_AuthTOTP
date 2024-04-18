using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using static Testing_AuthTOTP.Models.AuthModel;

namespace Testing_AuthTOTP.Models
{
    public interface IAuthModel
    {
        //  Task<UserMst> Register(UserMst u, string password);
        //Task<UserMst> Login(string username, string password);
        //  Task<bool> UserExists(string username);
        Task<bool> RegisterUser(LoginUser User);
        Task<bool> UserExists(string username);
        Task<bool> Login(LoginUser User);
        Task<string> GenerateWebToken(LoginUser User);
        Task<string> OnGetAsync(LoginUser User);
        Task<bool> OnVarifyAsync(LoginUser User, string code);

    }
    public class AuthModel: IAuthModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<AuthModel> _logger;
        private readonly IConfiguration _config;
        private readonly UrlEncoder _urlEncoder;

        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        public AuthModel(SignInManager<IdentityUser> signInManager, ILogger<AuthModel> logger
                           , UserManager<IdentityUser> userManager, IConfiguration config
                           , UrlEncoder urlEncoder)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManager = userManager;
            _config = config;
            _urlEncoder = urlEncoder;
        }



        [BindProperty]
        public InputModel Input { get; set; }

        public bool RememberMe { get; set; }

        public string ReturnUrl { get; set; }

        public class InputModel
        {
            [Required]
            [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Text)]
            [Display(Name = "Authenticator code")]
            public string TwoFactorCode { get; set; }

            [Display(Name = "Remember this machine")]
            public bool RememberMachine { get; set; }
        }

        public class LoginUser
        {
            public string? UserName { get; set; }
            
            public string? Password { get; set; }

        }
        public async Task<bool> OnGetAsync(bool rememberMe, string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            ReturnUrl = returnUrl;
            RememberMe = rememberMe;

            return true;
        }

        public async Task<string> OnPostAsync(InputModel input)
        {
            /*if (!ModelState.IsValid)
            {
                return Page();
            }*/

            //returnUrl = returnUrl ?? Url.Content("~/");

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var authenticatorCode = input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, true, true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", user.Id);
                return user.Id;
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID '{UserId}' account locked out.", user.Id);
                return "LockedOut";
            }
            else
            {
                _logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", user.Id);
                //ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return "null";
            }
        }
        public async Task<bool> Login(LoginUser User)
        {
            if (string.IsNullOrEmpty(User.UserName)) new InvalidOperationException($"User Name Is Required !.");
            if (string.IsNullOrEmpty(User.Password)) new InvalidOperationException($"Password is Required !.");
            var result = await _userManager.FindByEmailAsync(User.UserName);
            if (result is null)
            {
                return false;
            }

            return await _userManager.CheckPasswordAsync(result, User.Password);
        }
        public async Task<bool> RegisterUser(LoginUser User )
        {
            if(string.IsNullOrEmpty(User.UserName)) new InvalidOperationException($"User Name Is Required !.");
            if(string.IsNullOrEmpty(User.Password)) new InvalidOperationException($"Password is Required !.");

            var IdentityUser = new IdentityUser
            {
                UserName = User.UserName,
                Email = User.UserName,
            };
            var result = await _userManager.CreateAsync(IdentityUser, User.Password);

            return result.Succeeded;
        }

        public async Task<string> GenerateWebToken(LoginUser User)
        {
            IEnumerable<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email,User.UserName),
                new Claim(ClaimTypes.Role,"Admin")
            };
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Key").Value));
            SigningCredentials signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var securityToken = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(3),
                issuer : _config.GetSection("Jwt:Issuer").Value,
                audience : _config.GetSection("Jwt:Audience").Value,
                signingCredentials: signingCred
                );
            var token = new JwtSecurityTokenHandler().WriteToken(securityToken);
            return token;
        }
        public async Task<bool> UserExists(string username)
        {
            var name = await _userManager.FindByNameAsync(username);
            if (name !=null)
                return true;
            return false;
        }
        /*private void setHashAndSalt(string password)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                this.passwordSalt = hmac.Key;
                this.passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

            }
        }*/

        public async Task<string> OnGetAsync(LoginUser User)
        {
            var user = await _userManager.FindByEmailAsync(User.UserName);
            if (user == null)
            {
                return "Unable to load user with ID '"+ User.UserName + "'.";
            }

            var URI =await LoadSharedKeyAndQrCodeUriAsync(user);

            return URI;
        }
        private async Task<string> LoadSharedKeyAndQrCodeUriAsync(IdentityUser user)
        {
            // Load the authenticator key & QR code URI to display on the form
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var SharedKey = FormatKey(unformattedKey);

            var email = await _userManager.GetEmailAsync(user);
            var AuthenticatorUri = GenerateQrCodeUri(email, unformattedKey);
            return AuthenticatorUri;
        }

        private string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
            AuthenticatorUriFormat,
                _urlEncoder.Encode("Eduvitech"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }

        public async Task<bool> OnVarifyAsync(LoginUser User,string code)
        {
            var user = await _userManager.FindByEmailAsync(User.UserName);
            if (user == null)
            {
                return false;
            }
             var token = await LoadSharedKeyAndQrCodeUriAsync(user);

            // Strip spaces and hypens
            var verificationCode = code.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                // ModelState.AddModelError("Input.Code", "Verification code is invalid.");
                token = await LoadSharedKeyAndQrCodeUriAsync(user);
                return false;
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            var userId = await _userManager.GetUserIdAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app.", userId);
            return true;
            // StatusMessage = "Your authenticator app has been verified.";

            /*if (await _userManager.CountRecoveryCodesAsync(user) == 0)
            {
               // var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                //RecoveryCodes = recoveryCodes.ToArray();
                return false;
            }
            else
            {
                return true;
            }*/
        }
    }
}
