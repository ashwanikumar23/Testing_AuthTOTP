using System.ComponentModel.DataAnnotations;

namespace Testing_AuthTOTP.Models
{
    public class UserModel
    {
        [Key]
        public int UserId { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
        public string? Roles { get; set; }
        public string? Email { get; set; }
    }
}
