using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace SslCertBinding.Net.Sample.Tests
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
			// ReSharper disable InconsistentNaming
			public IPEndPoint ipport;
			public string certhash;
			public Guid appid;
			public string certstorename = null;
			public bool? verifyclientcertrevocation = null;
			public bool? verifyrevocationwithcachedclientcertonly = null;
			public bool? usagecheck = null;
			public int? revocationfreshnesstime = null;
			public int? urlretrievaltimeout = null;
			public string sslctlidentifier = null;
			public string sslctlstorename = null;
			public bool? dsmapperusage = null;
			public bool? clientcertnegotiation = null;
			// ReSharper restore InconsistentNaming
		}

		public static CommandResult Show(IPEndPoint ipPort = null, bool throwExcepton = false) {
			return ExecCommand(string.Format("http show sslcert {0}", ipPort), throwExcepton);
		}

		public static bool IpPortIsPresentInConfig(IPEndPoint ipPort) {
			var result = Show(ipPort);
			return result.IsSuccessfull;
		}

		public static void Add(Options options) {
			if (options == null)
				throw new ArgumentNullException("options");
			StringBuilder sb = new StringBuilder();

			foreach (var optionField in options.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public)) {
				object valObj = optionField.GetValue(options);
				if (valObj != null) {
					string valStr;
					if (optionField.FieldType == typeof(bool?))
						valStr = ((bool?)valObj).Value ? "enable" : "disable";
					else if (optionField.FieldType == typeof(Guid))
						valStr = ((Guid)valObj).ToString("B");
					else
						valStr = valObj.ToString();

					sb.AppendFormat(" {0}={1}", optionField.Name, valStr);
				}
			}

			ExecCommand(string.Format("http add sslcert {0}", sb), true);
		}

		public static void RemoveIpEndPoints(string thumbprint) {
			foreach (var ipEndPoint in GetIpEndPoints(thumbprint)) {
				ExecDelete(ipEndPoint);
			}
		}

		public static IPEndPoint[] GetIpEndPoints(string thumbprint = null) {
			var result = Show(throwExcepton: true);
			var pattern = string.Format(@"\s+IP:port\s+:\s+(\S+?)\s+Certificate Hash\s+:\s+{0}\s+",
				string.IsNullOrEmpty(thumbprint) ? @"\S+" : thumbprint);
			var matches = Regex.Matches(result.Output, pattern,
				RegexOptions.IgnoreCase | RegexOptions.CultureInvariant |
				RegexOptions.Singleline);

			var endPoints = matches.Cast<Match>().Select(match => IpEndpointTools.ParseIpEndPoint(match.Groups[1].Value)).ToArray();
			return endPoints;
		}

		private static CommandResult ExecCommand(string arguments, bool throwExcepton) {
			var psi = new ProcessStartInfo("netsh") {
				Arguments = arguments,
				CreateNoWindow = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
			};

			CommandResult commandResult;
			using (var process = new Process { StartInfo = psi }) {
				var outputBuilder = new StringBuilder();
				process.OutputDataReceived += (sender, e) => { outputBuilder.AppendLine(e.Data); };
				process.ErrorDataReceived += (sender, e) => { outputBuilder.AppendLine(e.Data); };
				
				process.Start();
				
				process.BeginOutputReadLine();
				process.BeginErrorReadLine();

				process.WaitForExit();

				commandResult = new CommandResult { ExitCode = process.ExitCode, Output = outputBuilder.ToString() };
			}

			if (throwExcepton && !commandResult.IsSuccessfull)
				throw new InvalidOperationException(string.Format("{0}: {1}", commandResult.ExitCode, commandResult.Output));
			return commandResult;
		}

		private static void ExecDelete(IPEndPoint ipPort) {
			ExecCommand(string.Format("http delete sslcert {0}", ipPort), true);
		}
	}
}