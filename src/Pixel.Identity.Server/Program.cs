using FluentValidation;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
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
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using MudBlazor;
using MudBlazor.Services;
using Pixel.Identity.Core;
using Pixel.Identity.Core.Plugins;
using Pixel.Identity.Server.Areas.Identity;
using Pixel.Identity.Server.Data;
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
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Primitives;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Logging;
using System.Security.Authentication;
using System.Security.Claims;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

Func<HttpMessageHandler> customHttpHandler = () =>
{   
    var handler = new HttpClientHandler();
    // handler.ClientCertificates.Add(clientCertificate);
    // handler.ClientCertificateOptions = ClientCertificateOption.Manual;
    handler.SslProtocols = SslProtocols.Tls12;
    // handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => 
    // { 
    //     if(builder.Environment.IsDevelopment()) 
    //     {
    //         return true;
    //     }
    //     else
    //     {
    //         return sslPolicyErrors == SslPolicyErrors.None ;
    //     }

    // };

    return handler;
};

// Add services to the container.
builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(options =>
    {
        // 注意枚举类型的含义
        options.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        options.AllowAnyClientCertificate();
        
    });

});

IdentityModelEventSource.ShowPII = true;

var pluginsOptions = new PluginOptions();
builder.Configuration.GetSection(PluginOptions.Plugins).Bind(pluginsOptions);

//To forward the scheme from the proxy in non - IIS scenarios
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});


//Add plugin assembly type to application part so that controllers in this assembly can be discovered by asp.net
builder.Services.AddControllersWithViews()
.AddJsonOptions(options =>
{
    //设置bool获取格式
    options.JsonSerializerOptions.Converters.Add(new BoolJsonConverter()); 
    options.JsonSerializerOptions.Converters.Add(new StringJsonConverter());   
    //获取或设置要在转义字符串时使用的编码器
    options.JsonSerializerOptions.Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
    //空的字段不返回
    // options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    //允许 JSON 格式的评论
    options.JsonSerializerOptions.ReadCommentHandling = JsonCommentHandling.Skip;
    //允许在 JSON 中使用尾随逗号
    options.JsonSerializerOptions.AllowTrailingCommas = true;

});
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
// var baseAddress = new Uri(builder.Configuration["BaseAddress"]);
builder.Services.AddHttpClient();
builder.Services.AddSwaggerGen(c =>
{
    c.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
});


// builder.Services.AddScoped<ICertificateValidationService,CertificateValidationService>();
builder.Services.AddScoped<AuthenticationStateProvider, RevalidatingIdentityAuthenticationStateProvider<ApplicationUser>>();



// builder.Services.AddHttpClient("Pixel.Identity.UI", client => client.BaseAddress = baseAddress);

// // Supply HttpClient instances that include access tokens when making requests to the server project
// builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("Pixel.Identity.UI"));
// builder.Services.AddHttpClient<IUserRolesService, UserRolesService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IUsersService, UsersService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IApplicationService, ApplicationService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IScopeService, ScopeService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IAccountService, AccountService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IExternalLoginsService, ExternalLoginsService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IAuthenticatorService, AuthenticatorService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IRoleClaimsService, RoleClaimsService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);
// builder.Services.AddHttpClient<IUserClaimsService, UserClaimsService>(client => client.BaseAddress = baseAddress)
// .ConfigurePrimaryHttpMessageHandler(customHttpHandler);

builder.Services.AddScoped<TokenProvider>();
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<IScopeService, ScopeService>();

builder.Services.AddScoped<IUserRolesService, UserRolesService>();
builder.Services.AddScoped<IUsersService, UsersService>();
builder.Services.AddScoped<IApplicationService, ApplicationService>();
builder.Services.AddScoped<IExternalLoginsService, ExternalLoginsService>();
builder.Services.AddScoped<IAuthenticatorService, AuthenticatorService>();
builder.Services.AddScoped<IRoleClaimsService, RoleClaimsService>();
builder.Services.AddScoped<IUserClaimsService, UserClaimsService>();

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

var authenticationBuilder = builder.Services.AddAuthentication(
    options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;       
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
        options.SlidingExpiration = true;
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {                    
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.SignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
        options.ClientId = "pixel-identity-ui2";                    
        // options.Authority = "https://localhost:7109/pauth";  
          options.Authority = "https://pixel.docker.localhost/pauth";
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

    #region Configure core setup for OpenIddict and delegate database configuration to DbStore plugin
    p.ConfigureIdentity(builder.Configuration, s)
    .AddSignInManager()
    .AddDefaultTokenProviders();

    s.ConfigureApplicationCookie(opts =>
    {
        opts.LoginPath = "/Account/Login";
    });

    var openIdBuilder = s.AddOpenIddict()
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
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
    });
    p.ConfigureOpenIdDictStore(builder.Configuration, openIdBuilder);
    #endregion

    p.AddServices(s);
});

builder.Services.AddAuthorizationCore(options =>
{
    options.AddPolicy(Policies.CanManageApplications, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(Claims.ReadWriteClaim, "applications");
    });
    options.AddPolicy(Policies.CanManageScopes, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(Claims.ReadWriteClaim, "scopes");
    });
    options.AddPolicy(Policies.CanManageUsers, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim(Claims.ReadWriteClaim, "users");
    });
    options.AddPolicy(Policies.CanManageRoles, policy =>
    {
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

// app.UsePathBase("/pauth");

// app.UseSerilogRequestLogging();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Pixel Persistence V1");
});

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
        AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme            
    }
);
app.MapFallbackToPage("/_Host");

app.Run();
