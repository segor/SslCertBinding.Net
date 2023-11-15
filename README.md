# SslCertBinding.Net
SslCertBinding.Net is a library for .NET and Windows and provides a simple API to add, remove or retrieve bindings between a https port and a SSL certificate.

This library can be considered as a programmatic alternative to Windows command line tools `netsh http show|add|delete sslcert` or `httpcfg query|set|delete ssl`. 

## Installation
SslCertBinding.Net is available as a [NuGet package](http://www.nuget.org/packages/SslCertBinding.Net/).
```powershell
Install-Package SslCertBinding.Net -Pre
```

## Usage
```c#
ICertificateBindingConfiguration config = new CertificateBindingConfiguration();
var ipPort = new IPEndPoint(IPAddress.Parse("0.0.0.0"), 443); 
var certificateThumbprint = "372680E4AEC4A57CAE698307347C65D3CE38AF60";
var appId = Guid.Parse("214124cd-d05b-4309-9af9-9caa44b2b74a");

// add a new binding record
config.Bind( new CertificateBinding(
	certificateThumbprint, StoreName.My, ipPort, appId));

// get the binding record
var certificateBinding = config.Query(ipPort)[0];

// set an option and update the binding record
certificateBinding.Options.DoNotVerifyCertificateRevocation = true;
config.Bind(certificateBinding);

// remove the binding record
config.Delete(ipPort);
```
## FAQ

### Why unit tests are failing on my PC?
Cerificates configuration needs elevated permissions. Run Visual Studio as an Administrator before running unit tests.

### I am getting the error "A specified logon session does not exist. It may have already been terminated". How to fix it?
Make sure that you have installed your certificate properly, certificate has a private key, your privaite key store is not broken, etc. Try binding your certificate with `netsh` CLI tool. If you get the same error it should not be a bug in `SslCertBinding.Net`. 
