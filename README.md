# SslCertBinding.Net
 [![](https://img.shields.io/nuget/v/SslCertBinding.Net)](https://www.nuget.org/packages/SslCertBinding.Net) [![](https://img.shields.io/nuget/dt/SslCertBinding.Net)](https://www.nuget.org/stats/packages/SslCertBinding.Net?groupby=Version) [![](https://github.com/segor/SslCertBinding.Net/actions/workflows/build.yaml/badge.svg?branch=master&event=push)](https://github.com/segor/SslCertBinding.Net/actions/workflows/build.yaml?query=branch%3Amaster+event%3Apush) [![](https://github.com/segor/SslCertBinding.Net/actions/workflows/codeql.yml/badge.svg?branch=master&event=push)](https://github.com/segor/SslCertBinding.Net/actions/workflows/codeql.yml) [![](https://codecov.io/gh/segor/SslCertBinding.Net/master/graph/badge.svg?token=034FB4PVRL)](https://app.codecov.io/gh/segor/SslCertBinding.Net/tree/master)

SslCertBinding.Net is a library for .NET and Windows and provides a simple API to add, remove or retrieve bindings between a https port and a SSL certificate.

This library can be considered as a programmatic alternative to Windows command line tools `netsh http show|add|delete sslcert` or `httpcfg query|set|delete ssl`.

**Important: The library uses the Win32 API and works on the Windows platform only.**

## Installation
To get started, add the [SslCertBinding.Net](https://www.nuget.org/packages/SslCertBinding.Net/) NuGet package to your project by running the following command:

```sh
dotnet add package SslCertBinding.Net
```

## Usage
The public API is centered on `SslBindingConfiguration`.

The current implementation supports these binding families:

- `ipport=<ip>:<port>`
- `hostnameport=<host>:<port>`
- `ccs=<port>`
- `scopedccs=<host>:<port>`

| Netsh shape | Recommended key type | Recommended binding type |
| --- | --- | --- |
| `ipport=1.1.1.1:443` | `IpPortKey` | `IpPortBinding` |
| `ipport=0.0.0.0:443` | `IpPortKey` | `IpPortBinding` |
| `hostnameport=www.contoso.com:443` | `HostnamePortKey` | `HostnamePortBinding` |
| `ccs=443` | `CcsPortKey` | `CcsPortBinding` |
| `scopedccs=www.contoso.com:443` | `ScopedCcsKey` | `ScopedCcsBinding` |

```c#
#nullable enable

var config = new SslBindingConfiguration();
var certificate = new SslCertificateReference("372680E4AEC4A57CAE698307347C65D3CE38AF60");
var appId = Guid.Parse("214124cd-d05b-4309-9af9-9caa44b2b74a");

config.Upsert(new IpPortBinding(
    new IpPortKey(IPAddress.Parse("0.0.0.0"), 443),
    certificate,
    appId));

config.Upsert(new HostnamePortBinding(
    new HostnamePortKey("www.contoso.com", 443),
    certificate,
    appId));

config.Upsert(new CcsPortBinding(
    new CcsPortKey(443),
    appId));

config.Upsert(new ScopedCcsBinding(
    new ScopedCcsKey("www.contoso.com", 443),
    appId));

IReadOnlyList<ISslBinding> allBindings = config.Query();
HostnamePortBinding? sniBinding = config.Find(new HostnamePortKey("www.contoso.com", 443));
IpPortBinding? ipBinding = config.Find(new IpPortKey(IPAddress.Parse("0.0.0.0"), 443));
CcsPortBinding? ccsBinding = config.Find(new CcsPortKey(443));
ScopedCcsBinding? scopedCcsBinding = config.Find(new ScopedCcsKey("www.contoso.com", 443));
HostnamePortBinding? sniBindingFromEndPoint = config.Find(new DnsEndPoint("www.contoso.com", 443).ToHostnamePortKey()!);
ScopedCcsBinding? scopedCcsBindingFromEndPoint = config.Find(new DnsEndPoint("www.contoso.com", 443).ToScopedCcsKey()!);
IpPortBinding? ipBindingFromEndPoint = config.Find(new IPEndPoint(IPAddress.Parse("0.0.0.0"), 443).ToIpPortKey()!);

if (sniBinding is not null)
{
    Console.WriteLine(sniBinding.Certificate.Thumbprint);
}

config.Delete(new HostnamePortKey("www.contoso.com", 443));
config.Delete(new IpPortKey(IPAddress.Parse("0.0.0.0"), 443));
config.Delete(new CcsPortKey(443));
config.Delete(new ScopedCcsKey("www.contoso.com", 443));
config.Delete(new DnsEndPoint("www.contoso.com", 443).ToHostnamePortKey());
config.Delete(new DnsEndPoint("www.contoso.com", 443).ToScopedCcsKey());
config.Delete(new IPEndPoint(IPAddress.Parse("0.0.0.0"), 443).ToIpPortKey()!);
```

If you want family-specific enumeration, you can use:

```c#
IReadOnlyList<IpPortBinding> ipBindings = config.Query<IpPortBinding>();
IReadOnlyList<HostnamePortBinding> hostnameBindings = config.Query<HostnamePortBinding>();
IReadOnlyList<CcsPortBinding> ccsBindings = config.Query<CcsPortBinding>();
IReadOnlyList<ScopedCcsBinding> scopedCcsBindings = config.Query<ScopedCcsBinding>();
```

Exact lookup uses `Find(...)`. It returns the matching binding or `null` when no binding exists for the specified key.

`SslCertificateReference` does not accept a `null` store name. Use `new SslCertificateReference(thumbprint)` when you want the default `MY` store, or pass an explicit non-null store name when you want a different store.

`IpPortKey`, `HostnamePortKey`, and `ScopedCcsKey` define implicit conversions to and from the matching `IPEndPoint` or `DnsEndPoint` shapes where that mapping is natural. `IPEndPoint.ToIpPortKey()` is the IP-family helper, while `DnsEndPoint` uses explicit `ToHostnamePortKey()` and `ToScopedCcsKey()` conversions so the hostname-based families stay unambiguous.

Only `IpPortBinding` and `HostnamePortBinding` expose `SslCertificateReference`. `CcsPortBinding` and `ScopedCcsBinding` rely on HTTP.sys central certificate store resolution and therefore do not carry certificate thumbprint/store state in the public model.

`BindingOptions` support is not identical across the CCS families. `ScopedCcsBinding` can use the shared option surface, but `CcsPortBinding` is currently limited to default options only because HTTP.sys rejects non-default plain CCS option combinations on environments where CCS support is available.

The type model uses a hybrid interface/class model:

- `ISslBinding` is the non-generic root for mixed-family enumeration.
- `SslBinding<TKey>` provides the typed `Key` plus shared binding-state implementation for each binding family.

## Legacy API
The legacy IP-only API remains available as a soft migration path:

1. `CertificateBinding`, `ICertificateBindingConfiguration`, and `CertificateBindingConfiguration` still ship in this version.
2. They are marked obsolete and hidden from IntelliSense for new code.
3. They remain intentionally limited to `ipport` bindings.
4. They do not enumerate or expose `hostnameport`/SNI bindings.

Legacy usage remains supported:

```c#
#pragma warning disable CS0618
var legacyConfig = new CertificateBindingConfiguration();
legacyConfig.Bind(new CertificateBinding(
    "372680E4AEC4A57CAE698307347C65D3CE38AF60",
    StoreName.My,
    new IPEndPoint(IPAddress.Any, 443),
    Guid.Parse("214124cd-d05b-4309-9af9-9caa44b2b74a")));

IReadOnlyList<CertificateBinding> legacyBindings = legacyConfig.Query();
#pragma warning restore CS0618
```

Recommended migration:

```c#
var migratedConfig = new SslBindingConfiguration();
migratedConfig.Upsert(new IpPortBinding(
    new IpPortKey(IPAddress.Any, 443),
    new SslCertificateReference(
        "372680E4AEC4A57CAE698307347C65D3CE38AF60",
        StoreName.My),
    Guid.Parse("214124cd-d05b-4309-9af9-9caa44b2b74a")));

IReadOnlyList<IpPortBinding> migratedBindings = migratedConfig.Query<IpPortBinding>();
```

## FAQ

### Why unit tests are failing on my PC?
Cerificates configuration needs elevated permissions. Run Visual Studio as an Administrator before running unit tests.

### I am getting the error "A specified logon session does not exist. It may have already been terminated". How to fix it?
Make sure that you have installed your certificate properly, certificate has a private key, your private key store is not broken, etc. Try binding your certificate with `netsh` CLI tool. If you get the same error it should not be a bug in `SslCertBinding.Net`.
