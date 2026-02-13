using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SslCertBinding.Net.Tests
{
    internal class CertConfigCmd
    {
        public class CommandResult
        {
            public int ExitCode { get; set; }
            public string Output { get; set; }
            public bool IsSuccessfull { get { return ExitCode == 0; } }
        }

        public class Options
        {
#pragma warning disable CA1051 // Do not declare visible instance fields
#pragma warning disable CS0649 // Field 'CertConfigCmd.Options.verifyclientcertrevocation' is never assigned to, and will always have its default value
            public BindingEndPoint endpoint;
            public string certhash;
            public Guid appid;
            public string certstorename;
            public bool? verifyclientcertrevocation;
            public bool? verifyrevocationwithcachedclientcertonly;
            public bool? usagecheck;
            public int? revocationfreshnesstime;
            public int? urlretrievaltimeout;
            public string sslctlidentifier;
            public string sslctlstorename;
            public bool? dsmapperusage;
            public bool? clientcertnegotiation;
#pragma warning restore CS0649 // Field 'CertConfigCmd.Options.verifyclientcertrevocation' is never assigned to, and will always have its default value
#pragma warning restore CA1051 // Do not declare visible instance fields
        }

        public static Task<CommandResult> Show(BindingEndPoint endPoint = null, bool throwExcepton = true)
        {
            var sb = new StringBuilder("http show sslcert");
            if (endPoint != null)
            {
                AppendArgument(sb, GetBindingTypeArgumentName(endPoint), endPoint.ToString());
            }
            return ExecCommand(sb.ToString(), throwExcepton);
        }

        public static async Task<bool> IpPortIsPresentInConfig(BindingEndPoint endPoint)
        {
            CommandResult result = await Show(endPoint, throwExcepton: false);
            return result.IsSuccessfull;
        }

        public static Task<CommandResult> Add(Options options)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var sb = new StringBuilder("http add sslcert");
            CultureInfo cultureInfo = CultureInfo.InvariantCulture;


            if (options.endpoint != null) {
                AppendArgument(sb, GetBindingTypeArgumentName(options.endpoint), options.endpoint.ToString());
                if (!options.endpoint.IsIpEndpoint)
                {
                    if (string.IsNullOrEmpty(options.certstorename))
                        options.certstorename = "MY"; // Default certificate store for hostname bindings, otherwise the command will fail.
                }
            }
            if (!string.IsNullOrEmpty(options.certhash))
                AppendArgument(sb, "certhash", options.certhash);
            if (options.appid != Guid.Empty)
                AppendArgument(sb, "appid", options.appid.ToString("B"));
            if (!string.IsNullOrEmpty(options.certstorename))
                AppendArgument(sb, "certstorename", options.certstorename);
            if (options.verifyclientcertrevocation.HasValue)
                AppendArgument(sb, "verifyclientcertrevocation", BoolToEnableDisable(options.verifyclientcertrevocation.Value));
            if (options.verifyrevocationwithcachedclientcertonly.HasValue)
                AppendArgument(sb, "verifyrevocationwithcachedclientcertonly", BoolToEnableDisable(options.verifyrevocationwithcachedclientcertonly.Value));
            if (options.usagecheck.HasValue)
                AppendArgument(sb, "usagecheck", BoolToEnableDisable(options.usagecheck.Value));
            if (options.revocationfreshnesstime.HasValue)
                AppendArgument(sb, "revocationfreshnesstime", options.revocationfreshnesstime.Value.ToString(cultureInfo));
            if (options.urlretrievaltimeout.HasValue)
                AppendArgument(sb, "urlretrievaltimeout", options.urlretrievaltimeout.Value.ToString(cultureInfo));
            if (!string.IsNullOrEmpty(options.sslctlidentifier))
                AppendArgument(sb, "sslctlidentifier", options.sslctlidentifier);
            if (!string.IsNullOrEmpty(options.sslctlstorename))
                AppendArgument(sb, "sslctlstorename", options.sslctlstorename);
            if (options.dsmapperusage.HasValue)
                AppendArgument(sb, "dsmapperusage", BoolToEnableDisable(options.dsmapperusage.Value));
            if (options.clientcertnegotiation.HasValue)
                AppendArgument(sb, "clientcertnegotiation", BoolToEnableDisable(options.clientcertnegotiation.Value));

            return ExecCommand(sb.ToString(), true);

            string BoolToEnableDisable(bool value) => value ? "enable" : "disable";
        }

        public static async Task RemoveBindingEndPoints(string thumbprint)
        {
            foreach (var endPoint in await GetBindingEndPoints(thumbprint))
            {
                await ExecDelete(endPoint);
            }
        }

        public static async Task<BindingEndPoint[]> GetBindingEndPoints(string thumbprint = null)
        {
            CommandResult result = await Show();
            string pattern = string.Format(CultureInfo.InvariantCulture, @"\s+(IP|Hostname):port\s+:\s+(\S+?)\s+Certificate Hash\s+:\s+{0}\s+",
                string.IsNullOrEmpty(thumbprint) ? @"\S+" : thumbprint);
            MatchCollection matches = Regex.Matches(result.Output, pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant |
                RegexOptions.Singleline);

            var endPoints = matches.Cast<Match>().Select(match => BindingEndPoint.Parse(match.Groups[2].Value)).ToArray();
            return endPoints;
        }

        private static async Task<CommandResult> ExecCommand(string arguments, bool throwExcepton)
        {
            var psi = new ProcessStartInfo("netsh")
            {
                Arguments = arguments,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            CommandResult commandResult;
            using (var process = new Process { StartInfo = psi })
            {
                var outputBuilder = new StringBuilder();
                process.OutputDataReceived += (sender, e) => { outputBuilder.AppendLine(e.Data); };
                process.ErrorDataReceived += (sender, e) => { outputBuilder.AppendLine(e.Data); };

                process.Start();

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                await process.WaitForExitAsync();

                commandResult = new CommandResult { ExitCode = process.ExitCode, Output = outputBuilder.ToString() };
            }

            if (throwExcepton && !commandResult.IsSuccessfull)
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "{0}: {1}", commandResult.ExitCode, commandResult.Output));
            return commandResult;
        }

        private static Task<CommandResult> ExecDelete(BindingEndPoint endPoint)
        {
            string bindingType = GetBindingTypeArgumentName(endPoint);
            return ExecCommand(string.Format(CultureInfo.InvariantCulture, "http delete sslcert {0}={1}", bindingType, endPoint), true);
        }

        private static string GetBindingTypeArgumentName(BindingEndPoint endPoint) => endPoint.IsIpEndpoint ? "ipport" : "hostnameport";
        private static void AppendArgument(StringBuilder sb, string argName, string argValue)
                => sb.AppendFormat(CultureInfo.InvariantCulture, " {0}={1}", argName, argValue);
    }
}
