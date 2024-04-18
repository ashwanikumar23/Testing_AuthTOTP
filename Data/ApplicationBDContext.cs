using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Testing_AuthTOTP.Models;

namespace Testing_AuthTOTP.Data
{
    public class ApplicationBDContext : IdentityDbContext
    {
        public ApplicationBDContext(DbContextOptions<ApplicationBDContext> options)
            : base(options)
        {
        }
    }
   /* public class ApplicationBDContext:DbContext
    {
        public ApplicationBDContext(DbContextOptions<ApplicationBDContext> options)
        : base(options)
        {
                
        }
        public DbSet<UserModel> User { get; set; }
    }*/
}
