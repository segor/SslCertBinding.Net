using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SslCertBinding.Net.Sample
{
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    internal static class Program
    {
        private static void Main(string[] args)
        {
            var configuration = new SslBindingConfiguration();

            string command = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty;
            switch (command)
            {
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
                    Console.WriteLine(
                        "Use\r\n" +
                        "'show' to list all SSL bindings,\r\n" +
                        "'show <family> <bindingKey>' to show one binding,\r\n" +
                        "'delete <family> <bindingKey>' to remove a binding, and\r\n" +
                        "'bind <family> <bindingKey> <appId> [<certificateThumbprint> <certificateStoreName>]' to add or update a binding.\r\n" +
                        "Families are 'ipport', 'hostnameport', 'ccs', and 'scopedccs'.");
                    break;
            }
        }

        private static void Show(string[] args, SslBindingConfiguration configuration)
        {
            Console.WriteLine("SSL Certificate bindings:\r\n-------------------------\r\n");
            var stores = new Dictionary<string, X509Store>(StringComparer.OrdinalIgnoreCase);
            IEnumerable<ISslBinding> bindings = args.Length switch
            {
                1 => configuration.Query(),
                3 => QueryOne(configuration, ParseBindingKey(ParseBindingKind(args[1]), args[2])),
                _ => throw new ArgumentException("Use 'show' or 'show <family> <bindingKey>'.", nameof(args)),
            };

            foreach (ISslBinding binding in bindings)
            {
                if (TryGetCertificateReference(binding, out SslCertificateReference certificateReference))
                {
                    if (!stores.TryGetValue(certificateReference.StoreName, out X509Store store))
                    {
                        store = new X509Store(certificateReference.StoreName, StoreLocation.LocalMachine);
                        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                        stores.Add(certificateReference.StoreName, store);
                    }

                    X509Certificate2 certificate = store.Certificates.Find(X509FindType.FindByThumbprint, certificateReference.Thumbprint, false)[0];
                    Console.WriteLine(
                        string.Format(
                            CultureInfo.InvariantCulture,
@" Key           : {0}
 Kind          : {1}
 Thumbprint    : {2}
 Subject       : {3}
 Issuer        : {4}
 Application ID: {5}
 Store Name    : {6}
",
                            binding.Key,
                            binding.Kind,
                            certificateReference.Thumbprint,
                            certificate.Subject,
                            certificate.Issuer,
                            binding.AppId,
                            certificateReference.StoreName));
                }
                else
                {
                    Console.WriteLine(
                        string.Format(
                            CultureInfo.InvariantCulture,
@" Key           : {0}
 Kind          : {1}
 Application ID: {2}
 Certificate   : Managed by Central Certificate Store
",
                            binding.Key,
                            binding.Kind,
                            binding.AppId));
                }
            }
        }

        private static void Bind(string[] args, SslBindingConfiguration configuration)
        {
            if (args.Length < 4)
            {
                throw new ArgumentException("Use 'bind <family> <bindingKey> <appId> [<certificateThumbprint> <certificateStoreName>]'.", nameof(args));
            }

            SslBindingKind kind = ParseBindingKind(args[1]);
            SslBindingKey key = ParseBindingKey(kind, args[2]);
            Guid appId = Guid.Parse(args[3]);

            switch (kind)
            {
                case SslBindingKind.IpPort:
                    if (args.Length != 6)
                    {
                        throw new ArgumentException("IP bindings require certificate thumbprint and store name.", nameof(args));
                    }

                    configuration.Upsert(new IpPortBinding((IpPortKey)key, new SslCertificateReference(args[4], args[5]), appId));
                    break;
                case SslBindingKind.HostnamePort:
                    if (args.Length != 6)
                    {
                        throw new ArgumentException("Hostname bindings require certificate thumbprint and store name.", nameof(args));
                    }

                    configuration.Upsert(new HostnamePortBinding((HostnamePortKey)key, new SslCertificateReference(args[4], args[5]), appId));
                    break;
                case SslBindingKind.CcsPort:
                    if (args.Length != 4)
                    {
                        throw new ArgumentException("CCS bindings do not accept certificate thumbprint or store name.", nameof(args));
                    }

                    configuration.Upsert(new CcsPortBinding((CcsPortKey)key, appId));
                    break;
                case SslBindingKind.ScopedCcs:
                    if (args.Length != 4)
                    {
                        throw new ArgumentException("Scoped CCS bindings do not accept certificate thumbprint or store name.", nameof(args));
                    }

                    configuration.Upsert(new ScopedCcsBinding((ScopedCcsKey)key, appId));
                    break;
                default:
                    throw new InvalidOperationException("Unsupported binding key type.");
            }

            Console.WriteLine("The binding record has been successfully applied.");
        }

        private static void Delete(string[] args, SslBindingConfiguration configuration)
        {
            if (args.Length != 3)
            {
                throw new ArgumentException("Use 'delete <family> <bindingKey>'.", nameof(args));
            }

            configuration.Delete(ParseBindingKey(ParseBindingKind(args[1]), args[2]));
            Console.WriteLine("The binding record has been successfully removed.");
        }

        private static IEnumerable<ISslBinding> QueryOne(SslBindingConfiguration configuration, SslBindingKey key)
        {
            switch (key)
            {
                case IpPortKey ipKey:
                    return configuration.Query(ipKey);
                case HostnamePortKey hostnameKey:
                    return configuration.Query(hostnameKey);
                case CcsPortKey ccsKey:
                    return configuration.Query(ccsKey);
                case ScopedCcsKey scopedCcsKey:
                    return configuration.Query(scopedCcsKey);
                default:
                    return Enumerable.Empty<ISslBinding>();
            }
        }

        private static SslBindingKind ParseBindingKind(string value)
        {
            switch (value?.Trim().ToLowerInvariant())
            {
                case "ipport":
                    return SslBindingKind.IpPort;
                case "hostnameport":
                    return SslBindingKind.HostnamePort;
                case "ccs":
                    return SslBindingKind.CcsPort;
                case "scopedccs":
                    return SslBindingKind.ScopedCcs;
                default:
                    throw new FormatException("Invalid binding family.");
            }
        }

        private static SslBindingKey ParseBindingKey(SslBindingKind kind, string value)
        {
            if (SslBindingKey.TryParse(value, kind, out SslBindingKey key))
            {
                return key;
            }

            throw new FormatException("Invalid binding key format.");
        }

        private static bool TryGetCertificateReference(ISslBinding binding, out SslCertificateReference certificateReference)
        {
            switch (binding)
            {
                case IpPortBinding ipBinding:
                    certificateReference = ipBinding.Certificate;
                    return true;
                case HostnamePortBinding hostnameBinding:
                    certificateReference = hostnameBinding.Certificate;
                    return true;
                default:
                    certificateReference = null;
                    return false;
            }
        }
    }
}
