using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Checkmarx.API;
using System.Linq;

namespace Sca_Recalculate
{
    class Program
    {
        public static IConfigurationRoot configuration;

        static void Main(string[] args)
        {
            ServiceCollection serviceCollection = new ServiceCollection();

            ConfigureServices(serviceCollection);
            
            string scaUsername  = configuration["SCA_USERNAME"];
            string scaPassword  = configuration["SCA_PASSWORD"];
            string scaTenant    = configuration["SCA_TENANT"];
            string scaACURL     = configuration["SCA_ACURL"];
            string scaAPIURL    = configuration["SCA_APIURL"];

            var client = new SCAClient(scaTenant, scaUsername, scaPassword, scaACURL, scaAPIURL);

            var projects = client.ClientSCA.GetProjectsAsync().Result;

            var projectsWithSucessfullScans = projects.Select(x => new {
                ProjectId = x.Id,
                LastScanId = x.AdditionalProperties
                    .Select(y => new { y.Key, y.Value })
                    .Where(y => y.Key == "lastSuccessfulScanId")
                    .ToList()
                    .Select(x => x.Value)
                    .FirstOrDefault()
            }).Where(x => x.LastScanId != null)
                .ToList();

            foreach (var p in projectsWithSucessfullScans)
            {
                var projectId = p.ProjectId;

                var lastSucessfullScanId = Guid.Parse(p.LastScanId.ToString());

                var riskReport = client.ClientSCA
                    .RiskReportsAsync(projectId, 1).Result.First();

                bool lastScanBefore13Dec = riskReport.CreatedOn.UtcDateTime 
                    <= new DateTime(2021,12,13);

                if(lastScanBefore13Dec)
                {
                    string newScanId = client.ClientSCA.RecalculateAsync(p.ProjectId).Result;
                    Console.WriteLine("triggered recalculation, new scanId : " + newScanId);
                }
            }

            Console.ReadKey();
        }

        private static void ConfigureServices(ServiceCollection serviceCollection)
        {
            // Build configuration
            configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetParent(AppContext.BaseDirectory).FullName)
#if NOTDEBUG
                .AddJsonFile("appsettings.json", true)
#endif
                .AddUserSecrets("3a219217-d81a-4f2b-a435-c40c96f4ea75")
                .AddEnvironmentVariables()
                .Build();
        }
    }
}