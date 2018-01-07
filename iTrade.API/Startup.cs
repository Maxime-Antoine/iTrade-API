using iTrade.API.Db;
using iTrade.API.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace iTrade.API
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public IHostingEnvironment Environment { get; }

        public Startup(IConfiguration configuration, IHostingEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseInMemoryDatabase("iTrade");
                options.UseOpenIddict();
            });

            //services.AddDbContext<AppDbContext>(options =>
            //{
            //    options.UseSqlServer(Configuration["ConnectionStrings:Default"]);
            //    options.UseOpenIddict();
            //});

            services.AddIdentity<AppUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            services.AddAuthentication()
                .AddOAuthValidation();

            services.AddOpenIddict(options =>
            {
                options.AddEntityFrameworkCoreStores<AppDbContext>()
                        .AddMvcBinders()
                        .EnableTokenEndpoint("/connect/token")
                        .EnableLogoutEndpoint("/connect/logout")
                        .AllowPasswordFlow()
                        .AllowRefreshTokenFlow();

                if (Environment.IsDevelopment())
                    options.Configure(config => config.ApplicationCanDisplayErrors = true)
                            .DisableHttpsRequirement();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();

            if (env.IsDevelopment())
                app.UseDeveloperExceptionPage();

            app.UseMvc();

            //create & seed database
            using (var serviceScope = app.ApplicationServices.CreateScope())
            {
                var db = serviceScope.ServiceProvider.GetService<AppDbContext>();
                db.Database.EnsureDeleted(); //DEBUG
                db.Database.EnsureCreated();
                _SeedIdentityAsync(serviceScope.ServiceProvider).Wait();
            }
        }

        private async Task _SeedIdentityAsync(IServiceProvider serviceProvider)
        {
            var db = serviceProvider.GetService<AppDbContext>();
            var roleStore = new RoleStore<IdentityRole>(db);
            var userStore = new UserStore<AppUser>(db);

            if (!roleStore.Roles.Any(r => r.Name == "Admin"))
            {
                await roleStore.CreateAsync(new IdentityRole() { Name = "Admin", NormalizedName = "ADMIN" });
                await roleStore.CreateAsync(new IdentityRole() { Name = "User", NormalizedName = "USER" });
            }

            var user = new AppUser
            {
                UserName = "Admin",
                NormalizedUserName = "ADMIN",
                Email = "test@test.com",
                NormalizedEmail = "TEST@TEST.com",
                EmailConfirmed = true,
                SecurityStamp = Guid.NewGuid().ToString("D")
            };

            if (!userStore.Users.Any(u => u.UserName == user.UserName))
            {
                var hasher = new PasswordHasher<AppUser>();
                var hashedPassword = hasher.HashPassword(user, "Test123");
                user.PasswordHash = hashedPassword;

                await userStore.CreateAsync(user);

                var userManager = serviceProvider.GetRequiredService<UserManager<AppUser>>();
                var dbUser = await userManager.FindByNameAsync(user.UserName);
                await userManager.AddToRoleAsync(dbUser, "Admin");
                await userManager.AddToRoleAsync(dbUser, "User");

                await userManager.AddClaimAsync(dbUser, new Claim("sub", dbUser.UserName));
            }

            await db.SaveChangesAsync();
        }
    }
}