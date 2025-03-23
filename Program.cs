using GENPORTCAL4_API.Common.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using StackExchange.Redis;
using System.Reflection;
using System.Text;

var aspnetcoreENV = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");

string _assmName = Assembly.GetExecutingAssembly().GetName().Name ?? "GenPortCal4_API";
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://*:5001");
AppSetting.Configuration = builder.Configuration;

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddHttpContextAccessor();
builder.Services.AddAutoScope();
builder.Services.AddMvc(option => option.Conventions.Add(new JwtAuthorizationConvention("JwtPolicy", Convert.ToBoolean(builder.Configuration["Jwt:Authen"]), builder?.Configuration["Jwt:ActionIgnore"]?.Split(',')))).AddNewtonsoftJson();
//Authen 1
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy",
        builder => builder.AllowAnyOrigin()
          .AllowAnyMethod()
          .AllowAnyHeader()
    //.AllowCredentials()
    .Build());
});

//Authen 2
try
{
    var accessRedis = $"{builder.Configuration["Redis:Host"]}:{builder.Configuration["Redis:Port"]},Password={builder.Configuration["Redis:Password"]}";
    var _redis = ConnectionMultiplexer.Connect(accessRedis);
    builder.Services.AddSingleton<IConnectionMultiplexer>(_redis);
}
catch { /**/ }
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
 .AddJwtBearer(options =>
 {
     options.RequireHttpsMetadata = false;
     options.TokenValidationParameters = new TokenValidationParameters
     {
         ValidateIssuer = true,
         ValidateAudience = true,
         ValidateLifetime = true,
         ValidateIssuerSigningKey = true,
         ValidIssuer = builder.Configuration["Jwt:Issuer"],
         ValidAudience = builder.Configuration["Jwt:Issuer"],
         IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
     };
 });
builder.Services.AddAuthorization(option =>
{
    option.AddPolicy("JwtPolicy", builder =>
    {
        builder.RequireAuthenticatedUser();
        builder.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
    });
});
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = $"{AppSetting.AssemblyName} ({DateTime.Now.ToString("dd/MM/yyyy-HH:mm")}) - {aspnetcoreENV}", Version = "v1" });
    c.AddSecurityDefinition("Login", new OpenApiSecurityScheme
    {
        Name = "AccessKey",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Login",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = $@"Standard Private-Authen header using the Login scheme. Example: ""[Username & Password Encryption]"" 
                        <br>Test Key (actor: ChangeCust, role: ADMIN) <br />
                        <br>Please copy text below and paste in value input. <br />
                        <textarea readonly style='height:150px;min-height:unset;'>
                            UDQyMDEwMDVfMDQtMDgtMjAyMi0wOToyODoxOQ==
                        </textarea>"
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = $@"Standard Authorization header using the Bearer scheme. Example: ""bearer [token]"" 
                        <br>Test Key (actor: Note, role: ADMIN) <br />
                        <br>Please copy text below and paste in value input. <br /> 
                        <textarea readonly style='height:150px;min-height:unset;'>
                            Bearer {aspnetcoreENV?.GetBearerSchem()}
                        </textarea>"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Login",
                },
            },
            new string[] {}
        }
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsProduction())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("../swagger/v1/swagger.json", $"{AppSetting.AssemblyName} v1"));
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

public static class AppSetting
{
    public static IConfiguration? Configuration { get; set; }
    public static string? AssemblyName { get; set; } = Assembly.GetExecutingAssembly().GetName().Name;
    public static string? SystemMessage(string? code) => Configuration?[$"SystemMessage:{code?.ToUpper()}"];
}

public static class SetupServiceLifeTime
{
    public static void AddAutoScope(this IServiceCollection services)
    {
        List<Type> allType = new List<Type>();
        List<string> nsRange = new List<string> { $"{AppSetting.AssemblyName}.Services", $"{AppSetting.AssemblyName}.Common", $"{AppSetting.AssemblyName}.DataAccess" };
        nsRange.ForEach(n =>
        {
            List<Type> srvTyp = Assembly.GetExecutingAssembly().GetTypes()
                                    .Where(t => t.Namespace != null && t.Namespace.StartsWith(n))
                                    .Where(t => t.IsClass && !t.IsAbstract && t.IsPublic).ToList();

            allType.AddRange(srvTyp);
        });

        if (!allType.IsEmpty())
        {
            allType.ForEach(clss =>
            {
                var intrf = clss.GetInterfaces().FirstOrDefault();
                if (intrf != null)
                {
                    services.AddScoped(intrf, clss);
                }
                else
                {
                    services.AddScoped(clss);
                }
            });
        }
    }
}

public class JwtAuthorizationConvention : IApplicationModelConvention
{
    private readonly string[] _actionIgnore;
    private readonly string _policy;
    private readonly bool _auth;

    public JwtAuthorizationConvention(string policy, bool auth, string[] actionIgnore)
    {
        _policy = policy;
        _auth = auth;
        _actionIgnore = actionIgnore;
    }

    public void Apply(ApplicationModel application)
    {
        if (_auth)
        {
            application.Controllers.ToList().ForEach(controller =>
            {
                var isController = controller.Selectors.Any(x => x.AttributeRouteModel != null
                                                        && x.AttributeRouteModel.Template.ToLower().StartsWith("api"));
                if (isController)
                {
                    controller.Actions.ToList().ForEach(action =>
                    {
                        var isActionAuthen = _actionIgnore == null || _actionIgnore?.Contains(action.ActionName.ToLower()) == false;
                        if (isActionAuthen)
                        {
                            action.Filters.Add(new AuthorizeFilter(_policy));
                        }
                    });
                }
            });
        }
    }
}

public static class NswagExtensions
{
    public static string GetBearerSchem(this string env)
    {
        string token = "";
        try
        {
            if (env.ToLower() == "development")
            {
                token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA5LzA5L2lkZW50aXR5L2NsYWltcy9hY3RvciI6ImFkbWluIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoidXNlciIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2hhc2giOiI1MGZmZjFhOC1kMTVjLTQ3NzEtOTM5Mi1lMzczODI4MzQ1MDkiLCJleHAiOjE3OTExMDA1NzcsIm5iZiI6MTY5NjQwNjE3NywiaXNzIjoiYWNjb3VudGluZ3N5c3RlbSIsImF1ZCI6ImFjY291bnRpbmdzeXN0ZW0ifQ.ttQZv5T2vd5fHPEnDE1U6nNuYsWAWcMgoy9h2OX3Q-8";
            }
            else if (env.ToLower() == "uat")
            {
                token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA5LzA5L2lkZW50aXR5L2NsYWltcy9hY3RvciI6ImFkbWluIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoidXNlciIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2hhc2giOiIyZTk3NDM1ZS02OTY2LTQ1ZTctOTdhZS05YWE1MTNkNzZiNjMiLCJleHAiOjE3OTExMDA1OTgsIm5iZiI6MTY5NjQwNjE5OCwiaXNzIjoiYWNjb3VudGluZ3N5c3RlbSIsImF1ZCI6ImFjY291bnRpbmdzeXN0ZW0ifQ.m0bP_4bWon6vpntG3OS3lyxf_jeDwh0hsjYqfXegXxo";
            }
            else if (env.ToLower() == "production")
            {
                token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA5LzA5L2lkZW50aXR5L2NsYWltcy9hY3RvciI6ImFkbWluIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoidXNlciIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2hhc2giOiIxZTUxYzE3MC00NjUzLTQ0OWUtYjZkZC1mMTA4MGM1MmE0MjQiLCJleHAiOjE3OTExMDA2MzEsIm5iZiI6MTY5NjQwNjIzMSwiaXNzIjoiYWNjb3VudGluZ3N5c3RlbSIsImF1ZCI6ImFjY291bnRpbmdzeXN0ZW0ifQ.56ZAR_JvLh6JFHIVoteixw8HZqMCv94d6zaFB7024ro";
            }

            return token;
        }
        catch
        {
            return token;
        }
    }
}
