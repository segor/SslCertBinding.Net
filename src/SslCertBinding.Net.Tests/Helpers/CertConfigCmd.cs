using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SslCertBinding.Net.Tests
{
    internal static class CertConfigCmd
    {
        public sealed class CommandResult
        {
            public int ExitCode { get; set; }

            public string Output { get; set; }

            public bool IsSuccessfull
            {
                get { return ExitCode == 0; }
            }
        }

        public sealed class Options
        {
#pragma warning disable CA1051 // Do not declare visible instance fields
#pragma warning disable CS0649 // Test option bag fields are populated selectively by tests.
            public SslBindingKey key;
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
#pragma warning restore CS0649 // Test option bag fields are populated selectively by tests.
#pragma warning restore CA1051 // Do not declare visible instance fields
        }

        public sealed class BindingRecord
        {
            public SslBindingKey Key { get; set; }

            public Guid AppId { get; set; }
        }

        public static Task<CommandResult> Show(IPEndPoint ipPort = null, bool throwExcepton = false)
        {
            return Show(ipPort == null ? (SslBindingKey)null : new IpPortKey(ipPort), throwExcepton);
        }

        public static Task<CommandResult> Show(SslBindingKey key, bool throwExcepton = false)
        {
            var sb = new StringBuilder("http show sslcert");
            if (key != null)
            {
                AppendArgument(sb, GetArgumentName(key.Kind), key.ToString());
            }

            return ExecCommand(sb.ToString(), throwExcepton);
        }

        public static async Task<bool> IpPortIsPresentInConfig(IPEndPoint ipPort)
        {
            return await BindingIsPresentInConfig(new IpPortKey(ipPort));
        }

        public static async Task<bool> BindingIsPresentInConfig(SslBindingKey key)
        {
            CommandResult result = await Show(key, throwExcepton: false);
            return result.IsSuccessfull;
        }

        public static Task<CommandResult> Add(Options options)
        {
            return ExecCommand(CreateAddCommand(options), true);
        }

        internal static string CreateAddCommand(Options options)
        {
            _ = options ?? throw new ArgumentNullException(nameof(options));

            var sb = new StringBuilder("http add sslcert");
            SslBindingKey key = options.key ?? (options.ipport == null ? null : new IpPortKey(options.ipport));
            bool expectsCertificate = key == null
                || key.Kind == SslBindingKind.IpPort
                || key.Kind == SslBindingKind.HostnamePort;
            if (key != null)
            {
                AppendArgument(sb, GetArgumentName(key.Kind), key.ToString());
                if (key.Kind == SslBindingKind.HostnamePort && string.IsNullOrEmpty(options.certstorename))
                {
                    options.certstorename = "MY";
                }
            }

            if (expectsCertificate && !string.IsNullOrEmpty(options.certhash))
                AppendArgument(sb, "certhash", options.certhash);
            if (options.appid != Guid.Empty)
                AppendArgument(sb, "appid", options.appid.ToString("B"));
            if (expectsCertificate && !string.IsNullOrEmpty(options.certstorename))
                AppendArgument(sb, "certstorename", options.certstorename);
            if (options.verifyclientcertrevocation.HasValue)
                AppendArgument(sb, "verifyclientcertrevocation", BoolToEnableDisable(options.verifyclientcertrevocation.Value));
            if (options.verifyrevocationwithcachedclientcertonly.HasValue)
                AppendArgument(sb, "verifyrevocationwithcachedclientcertonly", BoolToEnableDisable(options.verifyrevocationwithcachedclientcertonly.Value));
            if (options.usagecheck.HasValue)
                AppendArgument(sb, "usagecheck", BoolToEnableDisable(options.usagecheck.Value));
            if (options.revocationfreshnesstime.HasValue)
                AppendArgument(sb, "revocationfreshnesstime", options.revocationfreshnesstime.Value.ToString(CultureInfo.InvariantCulture));
            if (options.urlretrievaltimeout.HasValue)
                AppendArgument(sb, "urlretrievaltimeout", options.urlretrievaltimeout.Value.ToString(CultureInfo.InvariantCulture));
            if (!string.IsNullOrEmpty(options.sslctlidentifier))
                AppendArgument(sb, "sslctlidentifier", options.sslctlidentifier);
            if (!string.IsNullOrEmpty(options.sslctlstorename))
                AppendArgument(sb, "sslctlstorename", options.sslctlstorename);
            if (options.dsmapperusage.HasValue)
                AppendArgument(sb, "dsmapperusage", BoolToEnableDisable(options.dsmapperusage.Value));
            if (options.clientcertnegotiation.HasValue)
                AppendArgument(sb, "clientcertnegotiation", BoolToEnableDisable(options.clientcertnegotiation.Value));

            return sb.ToString();
        }

        public static Task<CommandResult> Delete(SslBindingKey key)
        {
            _ = key ?? throw new ArgumentNullException(nameof(key));
            return ExecDelete(key);
        }

        public static async Task RemoveBindings(string thumbprint)
        {
            foreach (SslBindingKey key in await GetBindingKeys(thumbprint))
            {
                await ExecDelete(key);
            }
        }

        public static async Task RemoveIpEndPoints(string thumbprint)
        {
            foreach (IpPortKey key in (await GetBindingKeys(thumbprint)).OfType<IpPortKey>())
            {
                await ExecDelete(key);
            }
        }

        public static async Task<IPEndPoint[]> GetIpEndPoints(string thumbprint = null)
        {
            return (await GetBindingKeys(thumbprint))
                .OfType<IpPortKey>()
                .Select(key => key.ToIPEndPoint())
                .ToArray();
        }

        public static async Task<SslBindingKey[]> GetBindingKeys(string thumbprint = null)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                return (await GetBindingRecords()).Select(record => record.Key).ToArray();
            }

            CommandResult result = await Show((SslBindingKey)null, throwExcepton: true);
            string pattern = string.Format(
                CultureInfo.InvariantCulture,
                @"\s+(IP|Hostname):port\s+:\s+(\S+?)\s+Certificate Hash\s+:\s+{0}\s+",
                thumbprint);
            MatchCollection certificateMatches = Regex.Matches(
                result.Output,
                pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline);

            return certificateMatches
                .Cast<Match>()
                .Select(match => SslBindingKey.Parse(match.Groups[2].Value, ParseBindingKind(match.Groups[1].Value)))
                .ToArray();
        }

        public static async Task<BindingRecord[]> GetBindingRecords()
        {
            CommandResult result = await Show((SslBindingKey)null, throwExcepton: true);
            Match keyRegex = null;
            var records = new System.Collections.Generic.List<BindingRecord>();
            SslBindingKey currentKey = null;
            Guid? currentAppId = null;

            foreach (string line in Regex.Split(result.Output, @"\r?\n"))
            {
                keyRegex = Regex.Match(
                    line,
                    @"^\s*(IP|Hostname|CCS|Scoped CCS):port\s*:\s*(\S+)\s*$",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (keyRegex.Success)
                {
                    if (currentKey != null && currentAppId.HasValue)
                    {
                        records.Add(new BindingRecord { Key = currentKey, AppId = currentAppId.Value });
                    }

                    currentKey = SslBindingKey.Parse(keyRegex.Groups[2].Value, ParseBindingKind(keyRegex.Groups[1].Value));
                    currentAppId = null;
                    continue;
                }

                if (currentKey == null)
                {
                    continue;
                }

                Match appIdRegex = Regex.Match(
                    line,
                    @"^\s*Application ID\s*:\s*(\{[0-9A-Fa-f\-]+\})\s*$",
                    RegexOptions.CultureInvariant);
                if (appIdRegex.Success)
                {
                    currentAppId = Guid.Parse(appIdRegex.Groups[1].Value);
                    continue;
                }

                if (string.IsNullOrWhiteSpace(line) && currentKey != null && currentAppId.HasValue)
                {
                    records.Add(new BindingRecord { Key = currentKey, AppId = currentAppId.Value });
                    currentKey = null;
                    currentAppId = null;
                }
            }

            if (currentKey != null && currentAppId.HasValue)
            {
                records.Add(new BindingRecord { Key = currentKey, AppId = currentAppId.Value });
            }

            return records.ToArray();
        }

        private static Task<CommandResult> ExecDelete(SslBindingKey key)
        {
            return ExecCommand(
                string.Format(
                    CultureInfo.InvariantCulture,
                    "http delete sslcert {0}={1}",
                    GetArgumentName(key.Kind),
                    key),
                true);
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
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "{0}: {1}", commandResult.ExitCode, commandResult.Output));
            }

            return commandResult;
        }

        private static string GetArgumentName(SslBindingKind kind)
        {
            switch (kind)
            {
                case SslBindingKind.IpPort:
                    return "ipport";
                case SslBindingKind.HostnamePort:
                    return "hostnameport";
                case SslBindingKind.CcsPort:
                    return "ccs";
                case SslBindingKind.ScopedCcs:
                    return "scopedccs";
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        private static SslBindingKind ParseBindingKind(string value)
        {
            switch (value.Trim().ToUpperInvariant())
            {
                case "IP":
                    return SslBindingKind.IpPort;
                case "HOSTNAME":
                    return SslBindingKind.HostnamePort;
                case "CCS":
                    return SslBindingKind.CcsPort;
                case "SCOPED CCS":
                    return SslBindingKind.ScopedCcs;
                default:
                    throw new FormatException("Unsupported netsh binding family label.");
            }
        }

        private static void AppendArgument(StringBuilder sb, string argName, string argValue)
        {
            sb.AppendFormat(CultureInfo.InvariantCulture, " {0}={1}", argName, argValue);
        }

        private static string BoolToEnableDisable(bool value)
        {
            return value ? "enable" : "disable";
        }
    }
}
