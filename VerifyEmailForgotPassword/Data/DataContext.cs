using Microsoft.EntityFrameworkCore;
using VerifyEmailForgotPassword.Models;

namespace VerifyEmailForgotPassword.Data
{
    public class DataContext : DbContext
    {
        private readonly IConfiguration _configuration;
        public DataContext(DbContextOptions<DataContext> options, IConfiguration configuration) : base(options) 
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            optionsBuilder
                .UseSqlServer(_configuration.GetSection("ConnectionStrings:Connection").Value);
        }

        public DbSet<User> Users { get; set; }
    }
}
