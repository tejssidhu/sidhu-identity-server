using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using System.Reflection;
using Microsoft.AspNetCore.Identity;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.EntityFramework.DbContexts;
using System.Linq;

namespace sidhu_identity_server
{
    public class Startup
    {
        public IHostingEnvironment HostingEnvironment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IHostingEnvironment env, IConfiguration config)
        {
            HostingEnvironment = env;
            Configuration = config;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            var connectionString = Configuration.GetConnectionString("IdentityServerStore");
			var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

			services.AddDbContext<ApplicationDbContext>(builder =>
				builder.UseSqlServer(connectionString, sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly)));

			services.AddIdentity<IdentityUser, IdentityRole>()
				.AddEntityFrameworkStores<ApplicationDbContext>();

			services.AddIdentityServer()
				.AddOperationalStore(options => 
					options.ConfigureDbContext = builder => 
						builder.UseSqlServer(connectionString, sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly)))
				.AddConfigurationStore(options =>
					options.ConfigureDbContext = builder =>
						builder.UseSqlServer(connectionString, sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly)))
				.AddAspNetIdentity<IdentityUser>()
				//.AddInMemoryClients(Clients.Get())
				//.AddInMemoryIdentityResources(Resources.GetIdentityResources())
				//.AddInMemoryApiResources(Resources.GetApiResources())
				//.AddTestUsers(Users.Get())
				.AddDeveloperSigningCredential();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

			InitializeDbTestData(app);

			app.UseIdentityServer();

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync("Hello World!");
            });
        }

		private static void InitializeDbTestData(IApplicationBuilder app)
		{
			using (var scope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
			{
				scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
				scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>().Database.Migrate();
				scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.Migrate();

				var context = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();

				if (!context.Clients.Any())
				{
					foreach (var client in Clients.Get())
					{
						context.Clients.Add(client.ToEntity());
					}
					context.SaveChanges();
				}

				if (!context.IdentityResources.Any())
				{
					foreach (var resource in Resources.GetIdentityResources())
					{
						context.IdentityResources.Add(resource.ToEntity());
					}
					context.SaveChanges();
				}

				if (!context.ApiResources.Any())
				{
					foreach (var resource in Resources.GetApiResources())
					{
						context.ApiResources.Add(resource.ToEntity());
					}
					context.SaveChanges();
				}

				var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
				if (!userManager.Users.Any())
				{
					foreach (var testUser in Users.Get())
					{
						var identityUser = new IdentityUser(testUser.Username)
						{
							Id = testUser.SubjectId
						};

						userManager.CreateAsync(identityUser, "Password123!").Wait();
						userManager.AddClaimsAsync(identityUser, testUser.Claims.ToList()).Wait();
					}
				}
			}
		}
	}
}
