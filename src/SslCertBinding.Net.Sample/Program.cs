using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net.Sample
{
	class Program
	{
		private static void Main(string[] args) {
			var binding = new CertificateBinding();

			string command = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty;

			switch (command){
				case "show":
					Show(binding);
					break;
				case "add":
					Add(args, binding);
					break;
				case "delete":
					Delete(args, binding);
					break;
				default:
					Console.WriteLine("Use 'show' command to show all SSL Certificate bindings, 'delete {IP:port}' to remove a binding and 'add {certificateThumbprint} {certificateStoreName} {IP:port} {appId}' to add a binding.");
					break;
			}
		}

		private static void Show(CertificateBinding binding){
			Console.WriteLine("SSL Certificate bindings:\r\n-------------------------");
			var stores = new Dictionary<string, X509Store>();
			var certificateBindings = binding.QueryBinding();
			foreach (var info in certificateBindings){
				X509Store store;
				if (!stores.TryGetValue(info.StoreName, out store)){
					store = new X509Store(info.StoreName, StoreLocation.LocalMachine);
					store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
					stores.Add(info.StoreName, store);
				}

				var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, info.Thumbprint, false)[0];
				Console.WriteLine("IP:port:\t{2}\r\nThumbprint:\t{0}\r\nSubject:\t{4}\r\nIssuer:\t\t{5}\r\nApplication ID:\t{3}\r\nStore Name:\t{1}\r\n",
					info.Thumbprint, info.StoreName, info.IpPort, info.AppId, certificate.Subject, certificate.Issuer);
			}
		}

		private static void Add(string[] args, CertificateBinding binding){
			var ipPort = args[3].Split(':');
			var endPoint = new IPEndPoint(IPAddress.Parse(ipPort[0]), int.Parse(ipPort[1]));
			binding.Bind(new CertificateBindingInfo(args[1], args[2], endPoint, Guid.Parse(args[4])));
		}

		private static void Delete(string[] args, CertificateBinding binding){
			var ipPort = args[1].Split(':');
			var endPoint = new IPEndPoint(IPAddress.Parse(ipPort[0]), int.Parse(ipPort[1]));
			binding.DeleteBinding(endPoint);
		}
	}
}
