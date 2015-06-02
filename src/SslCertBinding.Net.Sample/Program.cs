using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net.Sample
{
	class Program
	{
		private static void Main(string[] args) {
			var configuration = new CertificateBindingConfiguration();

			string command = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty;

			switch (command){
				case "show":
					Show(args, configuration);
					break;
				case "bind":
					Bind(args, configuration);
					break;
				case "delete":
					Delete(args, configuration);
					break;
				default:
					Console.WriteLine("Use \r\n'show [<IP:port>]' command to show all SSL Certificate bindings, \r\n'delete <IP:port>' to remove a binding and \r\n'bind <certificateThumbprint> <certificateStoreName> <IP:port> <appId>' to add or update a binding.");
					break;
			}
		}

		private static void Show(string[] args, CertificateBindingConfiguration configuration) {
			Console.WriteLine("SSL Certificate bindings:\r\n-------------------------\r\n");
			var stores = new Dictionary<string, X509Store>();
			var ipEndPoint = args.Length > 1 ? ParseIpEndPoint(args[1]) : null;
			var certificateBindings = configuration.Query(ipEndPoint);
			foreach (var info in certificateBindings){
				X509Store store;
				if (!stores.TryGetValue(info.StoreName, out store)){
					store = new X509Store(info.StoreName, StoreLocation.LocalMachine);
					store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
					stores.Add(info.StoreName, store);
				}

				var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, info.Thumbprint, false)[0];
				string certStr = String.Format(
@" IP:port        : {2}
 Thumbprint     : {0}
 Subject        : {4}
 Issuer         : {5}
 Application ID : {3}
 Store Name     : {1}
 Verify Client Certificate Revocation                   : {6}
 Verify Revocation Using Cached Client Certificate Only : {7}
 Usage Check                 : {8}
 Revocation Freshness Time   : {9}
 URL Retrieval Timeout       : {10}
 Ctl Identifier : {11}
 Ctl Store Name : {12}
 DS Mapper Usage             : {13}
 Negotiate Client Certificate: {14}
",
					info.Thumbprint, info.StoreName, info.IpPort, info.AppId, certificate.Subject, certificate.Issuer, 
					!info.Options.DoNotVerifyCertificateRevocation, info.Options.VerifyRevocationWithCachedCertificateOnly, !info.Options.NoUsageCheck,
					info.Options.RevocationFreshnessTime + (info.Options.EnableRevocationFreshnessTime ? string.Empty : " (disabled)"),
					info.Options.RevocationUrlRetrievalTimeout, info.Options.SslCtlIdentifier, info.Options.SslCtlStoreName, 
					info.Options.UseDsMappers, info.Options.NegotiateCertificate);
				Console.WriteLine(certStr);
			}
		}

		private static void Bind(string[] args, CertificateBindingConfiguration configuration){
			var endPoint = ParseIpEndPoint(args[3]);
			var updated = configuration.Bind(new CertificateBinding(args[1], args[2], endPoint, Guid.Parse(args[4])));
			Console.WriteLine(updated ? "The binding record has been successfully updated." : "The binding record has been successfully added.");
		}

		private static void Delete(string[] args, CertificateBindingConfiguration configuration){
			var endPoint = ParseIpEndPoint(args[1]);
			configuration.Delete(endPoint);
			Console.WriteLine("The binding record has been successfully removed.");
		}

		private static IPEndPoint ParseIpEndPoint(string str){
			var ipPort = str.Split(':');
			return new IPEndPoint(IPAddress.Parse(ipPort[0]), int.Parse(ipPort[1]));
		}
	}
}
