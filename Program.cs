using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using Checkmarx.API.SCA;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
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

            string scaUsername  = configuration["Username"];
            string scaPassword  = configuration["Password"];
            string scaTenant    = configuration["Tenant"];
            string scaACURL     = configuration["ACURL"];
            string scaAPIURL    = configuration["APIURL"];

            List<Vulnerability> Vulns = new List<Vulnerability>();

            string[] cves = new[]{
                "CVE-2021-44228",
                "CVE-2021-45105",
                "CVE-2021-45046"
            };

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

                var lastScanDate = riskReport.CreatedOn;

                var projectVulnerabilities = client.ClientSCA
                    .VulnerabilitiesAsync(lastSucessfullScanId).Result;

                var log4jVulnerabilites = projectVulnerabilities
                    .Select(x => x.CveName)
                    .Where(x => cves.Contains(x))
                    .Distinct()
                    .ToList();

                if (log4jVulnerabilites.Count > 0)
                {
                    string newScanId = client.ClientSCA.RecalculateAsync(p.ProjectId).Result;

                    Console.WriteLine(lastScanDate.ToUniversalTime());
                    Console.WriteLine("triggered recalculation, new scanId : " + newScanId);
                    Console.WriteLine(JsonSerializer.Serialize(log4jVulnerabilites, new JsonSerializerOptions { WriteIndented = true }));
                    Console.WriteLine(JsonSerializer.Serialize(p, new JsonSerializerOptions { WriteIndented = true }));
                }
            }

            Console.ReadKey();
        }

        private static void ConfigureServices(ServiceCollection serviceCollection)
        {
            // Build configuration
            configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetParent(AppContext.BaseDirectory).FullName)
#if DEBUG
                .AddJsonFile("appsettings.dev.json", false)
#else
                .AddJsonFile("appsettings.json", false)
#endif
                .Build();
        }
    }
}