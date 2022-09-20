using FluentValidation;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MudBlazor;
using MudBlazor.Services;
using OpenIddict.Validation.AspNetCore;
using Pixel.Identity.Core;
using Pixel.Identity.Core.Plugins;
using Pixel.Identity.Server.Areas.Identity;
using Pixel.Identity.Server.Extensions;
using Pixel.Identity.Server.Services;
using Pixel.Identity.Server.Utilities;
using Pixel.Identity.Server.Validations;
using Pixel.Identity.Shared;
using Pixel.Identity.Store.Sql.Shared.Models;
using Pixel.Identity.Shared.ViewModels;
using Quartz;
using Serilog;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Net.Http.Headers;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Primitives;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Logging;
using System.Security.Authentication;
using System.Security.Claims;
using System.Net;
using System.IdentityModel.Tokens.Jwt;


internal class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Func<HttpMessageHandler> customHttpHandler = () =>
        // {
        //     var handler = new HttpClientHandler();
        //     // handler.ClientCertificates.Add(clientCertificate);
        //     // handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        //     handler.SslProtocols = SslProtocols.Tls12;
        //     handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => 
        //     { 
        //         if(builder.Environment.IsDevelopment()) 
        //         {
        //             return true;
        //         }
        //         else
        //         {
        //             return sslPolicyErrors == SslPolicyErrors.None ;
        //         }

        //     };

        //     return handler;
        // };

        // Add services to the container.
        // builder.Services.Configure<KestrelServerOptions>(options =>
        // {
        //     options.ConfigureHttpsDefaults(options =>
        //     {
        //         // 注意枚举类型的含义
        //         options.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        //         options.AllowAnyClientCertificate();

        //     });

        // });

        IdentityModelEventSource.ShowPII = true;

        var pluginsOptions = new PluginOptions();
        builder.Configuration.GetSection(PluginOptions.Plugins).Bind(pluginsOptions);

        //用于调试找不到配置
        // var cs = builder.Configuration.GetSection(PluginOptions.Plugins);
        // if (cs.Value == null)
        // {                
        //     var config = new ConfigurationBuilder()
        //     .AddJsonFile(path: "appsettings.json", optional: false, reloadOnChange: true)
        //     .Build();
        //     config.GetSection(PluginOptions.Plugins).Bind(pluginsOptions);
        //     ChangeToken.OnChange(() => config.GetReloadToken(), () =>
        //     {                    
        //         config.GetSection(PluginOptions.Plugins).Bind(pluginsOptions);
        //     });

        // }
        // else
        // {
        //     cs.Bind(pluginsOptions);
        // }    


        //To forward the scheme from the proxy in non - IIS scenarios
        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
        });

        //Add plugin assembly type to application part so that controllers in this assembly can be discovered by asp.net
        builder.Services.AddControllersWithViews()
        .AddXmlSerializerFormatters()
        .AddNewtonsoftJson();

        // .AddJsonOptions(options =>
        // {
        //     //设置bool获取格式
        //     options.JsonSerializerOptions.Converters.Add(new BoolJsonConverter());
        //     options.JsonSerializerOptions.Converters.Add(new StringJsonConverter());
        //     //获取或设置要在转义字符串时使用的编码器
        //     options.JsonSerializerOptions.Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
        //     //空的字段不返回
        //     // options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        //     //允许 JSON 格式的评论
        //     options.JsonSerializerOptions.ReadCommentHandling = JsonCommentHandling.Skip;
        //     //允许在 JSON 中使用尾随逗号
        //     options.JsonSerializerOptions.AllowTrailingCommas = true;

        //     options.JsonSerializerOptions.PropertyNameCaseInsensitive = false;

        // });

        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor();
        // builder.Services.AddScoped<ICertificateValidationService,CertificateValidationService>();
        builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<ApplicationUser>>();

        builder.Services.AddScoped<TokenProvider>();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddScoped<CustomTokenHandler>();
        builder.Services.AddScoped<CustomMessageHandler>();      
        builder.Services.AddScoped<ICustomAuthenticationService, CustomAuthenticationService>();
        var baseAddress = new Uri(builder.Configuration["BaseAddress"]);
        // baseAddress = new Uri("https://localhost:7109");

        // builder.Services.AddSwaggerGen(c =>
        // {
        //     c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
        // });

        builder.Services.AddHttpClient("Pixel.Identity.UI", client => client.BaseAddress = baseAddress);

        // Supply HttpClient instances that include access tokens when making requests to the server project
        builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("Pixel.Identity.UI"));

        builder.Services.AddHttpClient<IUserRolesService, UserRolesService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;
        // .ConfigurePrimaryHttpMessageHandler(customHttpHandler);

        builder.Services.AddHttpClient<IUsersService, UsersService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;

        builder.Services.AddHttpClient<IApplicationService, ApplicationService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;
        // .ConfigurePrimaryHttpMessageHandler<CustomMessageHandler>();
        builder.Services.AddScoped<IScopeService, ScopeService>();
        builder.Services.AddHttpClient<IScopeService, ScopeService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Add("Accept", "application/json");
        })
        // .AddHttpMessageHandler<TokenHandler>()
        ;
        // .ConfigurePrimaryHttpMessageHandler<CustomMessageHandler>();

        builder.Services.AddHttpClient<IAccountService, AccountService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;

        builder.Services.AddHttpClient<IExternalLoginsService, ExternalLoginsService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;

        builder.Services.AddHttpClient<IAuthenticatorService, AuthenticatorService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;

        builder.Services.AddHttpClient<IRoleClaimsService, RoleClaimsService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;

        builder.Services.AddHttpClient<IUserClaimsService, UserClaimsService>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddHttpMessageHandler<CustomTokenHandler>()
        ;

        builder.Services.AddTransient<IValidator<ApplicationViewModel>, ApplicationDescriptionValidator>();
        builder.Services.AddTransient<IValidator<ScopeViewModel>, ScopeValidator>();
        builder.Services.AddTransient<IValidator<UserRoleViewModel>, UserRoleValidator>();


        builder.Services.AddMudServices(config =>
        {
            config.SnackbarConfiguration.PositionClass = Defaults.Classes.Position.TopRight;
            config.SnackbarConfiguration.PreventDuplicates = false;
            config.SnackbarConfiguration.NewestOnTop = false;
            config.SnackbarConfiguration.ShowCloseIcon = true;
            config.SnackbarConfiguration.VisibleStateDuration = 10000;
            config.SnackbarConfiguration.HideTransitionDuration = 500;
            config.SnackbarConfiguration.ShowTransitionDuration = 500;
        });

        var allowedOrigins = builder.Configuration["AllowedOrigins"];
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(
                builder =>
                {
                    foreach (var item in allowedOrigins?.Split(';') ?? Enumerable.Empty<string>())
                    {
                        builder.WithOrigins(item);
                    }
                    //This is required for pre-flight request for CORS
                    builder.AllowAnyHeader();
                    builder.AllowAnyMethod();
                    builder.AllowCredentials();
                });
        });

        builder.Services.AddPlugin<IServicePlugin>(pluginsOptions["EmailSender"].Single(), (p, s) =>
        {
            p.ConfigureService(s, builder.Configuration);
        });

        // var authenticationBuilder = builder.Services.AddAuthentication();

        var authenticationBuilder = builder.Services.AddAuthentication(
            options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                // options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme; 
            } 
            )
            .AddCookie(
                CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
                    options.SlidingExpiration = true;
                }
            )
            // .AddJwtBearer(options =>
            // {
            //     options.Audience = "https://localhost:7109";
            //     options.Authority = "https://pixel.docker.localhost/pauth";
            // })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                // options.SignInScheme=IdentityConstants.ExternalScheme;
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.SignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.ClientId = "pixel-identity-ui2";
                options.Authority = "https://localhost:7109/pauth";  
                // options.Authority = "https://pixel.docker.localhost/pauth";
                options.RequireHttpsMetadata = false;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;
                options.SaveTokens = true;
                options.Scope.Add("email");
                options.Scope.Add("roles");
                options.Scope.Add("offline_access");
                options.MapInboundClaims = false;
                options.TokenValidationParameters.NameClaimType = "name";
                options.TokenValidationParameters.RoleClaimType = "role";

                options.Events.OnUserInformationReceived += eventArgs =>
                {
                    // We get the AccessToken from the ProtocolMessage.
                    // WARNING: This might change based on what type of Authentication Provider you are using
                    var accessToken = eventArgs.ProtocolMessage.AccessToken;
                    // Console.WriteLine($"new初始化获取AccessToken={accessToken}");
                    eventArgs.Principal.AddIdentity(new ClaimsIdentity(
                        new Claim[]
                        {
                    // Make note of the claim with the name "access_token"
                    // We will use it in an Authentication Service for look up.
                    new Claim("access_token", accessToken)
                        }
                    ));

                    // Here we take the accessToken and put all the claims into another
                    // Identity on the users Principal, giving us access to them when needed.
                    var jwtToken = new JwtSecurityToken(accessToken);
                    eventArgs.Principal.AddIdentity(new ClaimsIdentity(
                        jwtToken.Claims,
                        "jwt",
                        eventArgs.Options.TokenValidationParameters.NameClaimType,
                        eventArgs.Options.TokenValidationParameters.RoleClaimType
                    ));
                    return Task.CompletedTask;
                };

            }
        );

        foreach (var externalProvider in pluginsOptions["OAuthProvider"])
        {
            builder.Services.AddPlugin<IExternalAuthProvider>(externalProvider, (p, s) =>
            {
                p.AddProvider(builder.Configuration, authenticationBuilder);
            });
        }

        builder.Services.AddPlugin<IDataStoreConfigurator>(pluginsOptions["DbStore"].Single(), (p, s) =>
        {
            p.ConfigureAutoMap(s);
            ConfigureOpenIddict(s, p);
            p.AddServices(builder.Services);
        });

        /// <summary>
        /// Configure core setup for OpenIddict and delegate database configuration to DbStore plugin
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configurator"></param>
        void ConfigureOpenIddict(IServiceCollection services, IDataStoreConfigurator configurator)
        {
            //Configure Identity will call services.AddIdentity which will AddAuthentication  
            configurator.ConfigureIdentity(builder.Configuration, services)
            .AddSignInManager()
            .AddDefaultTokenProviders();

            services.ConfigureApplicationCookie(opts =>
            {
                opts.LoginPath = "/Identity/Account/Login";
            });

            var openIdBuilder = services.AddOpenIddict()
            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                // Enable the authorization, logout, token and userinfo endpoints.
                options.SetAuthorizationEndpointUris("/connect/authorize")
                .SetLogoutEndpointUris("/connect/logout")
                .SetTokenEndpointUris("/connect/token")
                .SetUserinfoEndpointUris("/connect/userinfo")
                .SetIntrospectionEndpointUris("/connect/introspect")
                .SetDeviceEndpointUris("/connect/device")
                .SetVerificationEndpointUris("connect/verify");

                //when integration with third-party APIs/resource servers is desired
                options.DisableAccessTokenEncryption();

                // Disables the transport security requirement (HTTPS). Service is supposed
                // to run behind a reverse-proxy with tls termination
                options.UseAspNetCore().DisableTransportSecurityRequirement();

                options.DisableScopeValidation();

                options.AllowAuthorizationCodeFlow().AllowDeviceCodeFlow()
                    .AllowRefreshTokenFlow().AllowClientCredentialsFlow().AllowPasswordFlow();

                //https://documentation.openiddict.com/configuration/encryption-and-signing-credentials.html
                //OpenIdDict uses two types of credentials to secure the token it issues.
                //1.Encryption credentials are used to ensure the content of tokens cannot be read by malicious parties
                if (!string.IsNullOrEmpty(builder.Configuration["Identity:Certificates:EncryptionCertificatePath"]))
                {
                    var encryptionKeyBytes = File.ReadAllBytes(builder.Configuration["Identity:Certificates:EncryptionCertificatePath"]);
                    X509Certificate2 encryptionKey = new X509Certificate2(encryptionKeyBytes, builder.Configuration["Identity:EncryptionCertificateKey"],
                         X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
                    options.AddEncryptionCertificate(encryptionKey);
                }
                else
                {
                    options.AddDevelopmentEncryptionCertificate();
                }

                //2.Signing credentials are used to protect against tampering
                if (!string.IsNullOrEmpty(builder.Configuration["Identity:Certificates:SigningCertificatePath"]))
                {

                    var signingKeyBytes = File.ReadAllBytes(builder.Configuration["Identity:Certificates:SigningCertificatePath"]);
                    X509Certificate2 signingKey = new X509Certificate2(signingKeyBytes, builder.Configuration["Identity:SigningCertificateKey"],
                         X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);
                    options.AddSigningCertificate(signingKey);
                }
                else
                {
                    options.AddDevelopmentSigningCertificate();
                }

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
                .EnableLogoutEndpointPassthrough()
                .EnableTokenEndpointPassthrough()
                .EnableUserinfoEndpointPassthrough()
                .EnableStatusCodePagesIntegration();
            })
            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // An OAuth 2.0/OpenID Connect server configuration or an issuer address must be registered.
                // To use a local OpenIddict server, reference the 'OpenIddict.Validation.ServerIntegration' package and call 'services.AddOpenIddict().AddValidation().UseLocalServer()' to import the server settings.
                // To use a remote server, reference the 'OpenIddict.Validation.SystemNetHttp' package and call 'services.AddOpenIddict().AddValidation().UseSystemNetHttp()' and 'services.AddOpenIddict().AddValidation().SetIssuer()' to use server discovery.
                // Alternatively, you can register a static server configuration by calling 'services.AddOpenIddict().AddValidation().SetConfiguration()'.

                var signingKeyBytes = File.ReadAllBytes(builder.Configuration["Identity:Certificates:SigningCertificatePath"]);
                X509Certificate2 signingKey = new X509Certificate2(signingKeyBytes, builder.Configuration["Identity:SigningCertificateKey"],
                         X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);

                var encryptionKeyBytes = File.ReadAllBytes(builder.Configuration["Identity:Certificates:EncryptionCertificatePath"]);
                X509Certificate2 encryptionKey = new X509Certificate2(encryptionKeyBytes, builder.Configuration["Identity:EncryptionCertificateKey"],
                         X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.EphemeralKeySet);

                options.SetConfiguration(new OpenIdConnectConfiguration
                {
                    // Issuer = "https://pixel.docker.localhost/pauth",
                    Issuer = "https://localhost:7109/pauth",

                    SigningKeys = { new X509SecurityKey(signingKey) }
                });

                options.AddEncryptionCertificate(encryptionKey);

                options.UseAspNetCore();

            });
            configurator.ConfigureOpenIdDictStore(builder.Configuration, openIdBuilder);
        }

        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy(Policies.CanManageApplications, policy =>
            {
                policy.AuthenticationSchemes.Add(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.ReadWriteClaim, "applications");
            });
            options.AddPolicy(Policies.CanManageScopes, policy =>
            {
                policy.AuthenticationSchemes.Add(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                // policy.AuthenticationSchemes.Add(OpenIdConnectDefaults.AuthenticationScheme);        
                // policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);        
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.ReadWriteClaim, "scopes");
            });
            options.AddPolicy(Policies.CanManageUsers, policy =>
            {
                policy.AuthenticationSchemes.Add(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.ReadWriteClaim, "users");
            });
            options.AddPolicy(Policies.CanManageRoles, policy =>
            {
                policy.AuthenticationSchemes.Add(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.ReadWriteClaim, "roles");
            });
        });

        builder.Services.AddQuartz(options =>
        {
            options.UseMicrosoftDependencyInjectionJobFactory();
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        var app = builder.Build();
        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UsePathBase("/pauth");

        // app.UseSerilogRequestLogging();

        // app.UseSwagger();
        // app.UseSwaggerUI(c =>
        // {
        //     c.SwaggerEndpoint("/swagger/v1/swagger.json", "Pixel Persistence V1");
        // });

        app.UseHttpsRedirection();

        app.UseStaticFiles();

        app.UseRouting();
        app.UseCors();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapRazorPages();
        app.MapControllers();
        app.MapBlazorHub()
        .RequireAuthorization(
            new AuthorizeAttribute
            {
                AuthenticationSchemes = "OpenIdConnect,OpenIddict.Validation.AspNetCore,Cookies"
                // AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme
                // AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme
            }
        )
        ;
        app.MapFallbackToPage("/_Host");

        app.Run();
    }
}