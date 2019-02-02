using AspNet.Security.OpenIdConnect.Primitives;
using iTrade.API.Db;
using iTrade.API.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
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
            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIdConnectConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIdConnectConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIdConnectConstants.Claims.Role;
            });

            services.AddMvc();

            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseInMemoryDatabase("iTrade");
                // options.UseSqlServer(Configuration["ConnectionStrings:Default"]);
                options.UseOpenIddict();
            });

            services.AddIdentity<AppUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        options.UseEntityFrameworkCore()
                               .UseDbContext<AppDbContext>();
                    })
                    .AddServer(options =>
                    {
                        options.UseMvc();

                        options.EnableTokenEndpoint("/connect/token")
                            .AllowPasswordFlow()
                            .AllowRefreshTokenFlow();
                        
                        if (Environment.IsDevelopment())
                            options.Configure(config => config.ApplicationCanDisplayErrors = true)
                                    .DisableHttpsRequirement();
                    })
                    .AddValidation();

            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo { Title = "iTrade API", Version = "v1" });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();

            if (env.IsDevelopment())
                app.UseDeveloperExceptionPage();

            app.UseSwagger();

            app.UseSwaggerUI(options => 
            {
                options.SwaggerEndpoint("/swagger/v1/swagger.json", "iTrade API v1");
            });

            app.UseMvc();

            //create & seed database
            using (var serviceScope = app.ApplicationServices.CreateScope())
            {
                var db = serviceScope.ServiceProvider.GetService<AppDbContext>();
                db.Database.EnsureDeleted(); // DEBUG
                db.Database.EnsureCreated();

                _SeedIdentityAsync(serviceScope.ServiceProvider).Wait();
                _CreateOpendIddictClientsAsync(serviceScope.ServiceProvider).Wait();
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

        private async Task _CreateOpendIddictClientsAsync(IServiceProvider serviceProvider)
        {
            var manager = serviceProvider.GetRequiredService<OpenIddictApplicationManager<OpenIddictApplication>>();

            if (await manager.FindByClientIdAsync("itrade-web") == null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = "itrade-web",
                    DisplayName = "iTrade web client",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.Password,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken
                    }
                };


                var res = await manager.CreateAsync(descriptor);
            }
        }
    }
}