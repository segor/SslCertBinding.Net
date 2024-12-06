using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SslCertBinding.Net.Tests
{
    public class CertConfigCmd
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
            public IPEndPoint ipport;
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
#pragma warning restore CA1051 // Do not declare visible instance fields
        }

        public static Task<CommandResult> Show(IPEndPoint ipPort = null, bool throwExcepton = false)
        {
            return ExecCommand(string.Format(CultureInfo.InvariantCulture, "http show sslcert {0}", ipPort), throwExcepton);
        }

        public static async Task<bool> IpPortIsPresentInConfig(IPEndPoint ipPort)
        {
            CommandResult result = await Show(ipPort);
            return result.IsSuccessfull;
        }

        public static Task<CommandResult> Add(Options options)
        {
            _ = options ?? throw new ArgumentNullException(nameof(options));

            var sb = new StringBuilder();
            foreach (FieldInfo optionField in options.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public))
            {
                object valObj = optionField.GetValue(options);
                if (valObj != null)
                {
                    string valStr;
                    if (optionField.FieldType == typeof(bool?))
                        valStr = ((bool?)valObj).Value ? "enable" : "disable";
                    else if (optionField.FieldType == typeof(Guid))
                        valStr = ((Guid)valObj).ToString("B");
                    else
                        valStr = valObj.ToString();

                    sb.AppendFormat(CultureInfo.InvariantCulture, " {0}={1}", optionField.Name, valStr);
                }
            }

            return ExecCommand(string.Format(CultureInfo.InvariantCulture, "http add sslcert {0}", sb), true);
        }

        public static async Task RemoveIpEndPoints(string thumbprint)
        {
            foreach (IPEndPoint ipEndPoint in await GetIpEndPoints(thumbprint))
            {
                await ExecDelete(ipEndPoint);
            }

            CommandResult result = await Show(throwExcepton: true);
#pragma warning disable CA2249
            if (result.Output.IndexOf(thumbprint, StringComparison.InvariantCultureIgnoreCase) >= 0)
#pragma warning restore CA2249
            {
                throw new InvalidOperationException();
            }
        }

        public static async Task<IPEndPoint[]> GetIpEndPoints(string thumbprint = null)
        {
            CommandResult result = await Show(throwExcepton: true);
            string pattern = string.Format(CultureInfo.InvariantCulture, @"\s+IP:port\s+:\s+(\S+?)\s+Certificate Hash\s+:\s+{0}\s+",
                string.IsNullOrEmpty(thumbprint) ? @"\S+" : thumbprint);
            MatchCollection matches = Regex.Matches(result.Output, pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant |
                RegexOptions.Singleline);

            IPEndPoint[] endPoints = matches.Cast<Match>().Select(match => IpEndpointTools.ParseIpEndPoint(match.Groups[1].Value)).ToArray();
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

        private static Task<CommandResult> ExecDelete(IPEndPoint ipPort)
        {
            return ExecCommand(string.Format(CultureInfo.InvariantCulture, "http delete sslcert {0}", ipPort), true);
        }
    }
}
