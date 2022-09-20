using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using System;
using System.Net;

namespace Pixel.Identity.Provider;

public class Program
{
    public static int Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            .Enrich.FromLogContext()
            .WriteTo.Console()
            .CreateBootstrapLogger();

        try
        {
            CreateHostBuilder(args).Build().Run();
            return 0;
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Host terminated unexpectedly");
            return 1;
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
             .UseSerilog((context, services, configuration) =>
             {
                 configuration
                     .ReadFrom.Configuration(context.Configuration);
             })
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });
            // .ConfigureWebHostDefaults(options =>
            //     options.UseStartup<Startup>()
            //         .ConfigureKestrel((context, options) =>
            //         {
            //             options.Listen(IPAddress.Any, 44382, listionOptions =>
            //             {
            //                 listionOptions.UseHttps("/home/administrator/Projects/nets/pixel-identity/.certificates/localhost.pfx", string.Empty);
            //             });

            //         }));
}


