# SslCertBinding.Net AI Coding Agent Instructions

## Project Overview
**SslCertBinding.Net** is a Windows-only .NET library that provides a programmatic API for managing SSL certificate bindings (alternatives to `netsh http add|show|delete sslcert`). It wraps Windows HTTP Server API (httpapi.dll) via P/Invoke to configure HTTPS port and SSL certificate associations.

**Current Branch Focus**: `support-sni` - Adding support for Server Name Indication (SNI) through new `BindingEndPoint` abstraction (see PR #35).

## Architecture & Key Components

### Core API Layer
- **`CertificateBindingConfiguration`**: Main facade providing `Bind()`, `Query()`, `Delete()` operations on SSL bindings
- **`CertificateBinding`**: Data model representing a single SSL cert-to-endpoint association (thumbprint, store name, endpoint, appId, options)
- **`BindingEndPoint`**: NEW abstraction supporting both IP endpoints and DNS names (needed for SNI support)
  - Wraps `IPEndPoint` or `DnsEndPoint` internally
  - Use `IsIpEndpoint` property to distinguish types
  - Provides conversion methods: `ToIPEndPoint()`, `ToDnsEndPoint()`
- **`BindingOptions`**: Optional settings like revocation checks, certificate negotiation, SSL control identifiers

### Windows Interop Layer (`Interop/` folder)
- **`HttpApi.cs`**: P/Invoke wrapper for Windows httpapi.dll functions
  - `HttpInitialize()` / `HttpTerminate()` frame operations
  - `HttpSetServiceConfiguration()` / `HttpDeleteServiceConfiguration()` perform actual binding changes
  - `CallHttpApi()` ensures proper resource cleanup in finally blocks
- **`BindingStructures.cs`**: Marshals `CertificateBinding` to/from Windows `HTTP_SERVICE_CONFIG_SSL_SET` structures
- **`SockaddrStructure.cs`**: Low-level socket address marshaling for IP/DNS conversion

### Argument Validation
- Custom extension methods in `ArgumentValidation.cs`: `ThrowIfNull()`, `ThrowIfNullOrEmpty()`
- Used consistently for parameter validation throughout public API

## Multi-Target Build Strategy

**Target Frameworks** (see `SslCertBinding.Net.csproj`):
- `net462` (legacy)
- `net8.0-windows` (modern Windows-specific)  
- `net8.0` (cross-platform, but API throws `PlatformNotSupportedException` on non-Windows)

**Platform Support Attributes**: Use `[SupportedOSPlatform("windows")]` on Windows-specific types (NET5.0+)

**Build Process**:
```bash
cd src/
dotnet restore SslCertBinding.Net.sln
dotnet build SslCertBinding.Net.sln -c Release
```

## Testing & Workflow

### Test Execution Environment Constraints
⚠️ **CRITICAL**: Test execution differs significantly by platform:

**Linux (GitHub Codespace, Ubuntu):**
- Only **cross-platform tests** can execute (net8.0 framework)
- Windows-specific certificate binding tests are **automatically skipped** by the test framework (marked with `[SupportedOSPlatform("windows")]`)
- This is an environmental limitation, not something to "fix" - Linux cannot manipulate Windows SSL certificates
- Used for quick validation of non-Windows-specific logic only

**Windows (GitHub Actions, windows-latest):**
- All tests execute including Windows-specific certificate binding operations
- **This is the authoritative test environment** for validating certificate binding functionality
- Tests actually manipulate Windows SSL configuration and validate system state via netsh commands
- Must pass before merging SNI changes

### Test Execution Details
- **Unit Tests**: `CertificateBindingConfigurationTests`, `BindingEndPointTests`, `CertificateBindingTests`
- **Admin Requirement**: Tests need elevated permissions (run Visual Studio/terminal as Administrator)
- **Test Fixture**: Uses NUnit `[NonParallelizable]` because tests modify system SSL configuration
- **Test Helper**: `CertConfigCmd` shells out to `netsh http show|add|delete sslcert` to validate system state

```bash
# Local testing (requires admin)
cd src/
dotnet test SslCertBinding.Net.sln -c Release
```

### Critical Test Pattern
Tests use `CertConfigCmd` helper to interact with system via `netsh http show|add|delete sslcert`:
- Validates bindings against system state (not just API state)
- `CertConfigCmd.Add()` / `Show()` shell out to netsh for setup/verification
- Tests verify both API behavior AND resulting system configuration

### GitHub Actions Workflow
- **Windows Build Job**: Builds all 3 targets, runs tests with code coverage
- **Linux Test Job**: Runs net8.0 tests only (cross-platform verification)
- **NuGet Publish**: Automatic on tag push (only if not fork)
- Build/test runs on `push` to master/dev and on PRs to master

## Code Quality Standards

**Enforced via `Directory.Build.props`**:
- `TreatWarningsAsErrors=True`: All warnings must be fixed
- `EnableNETAnalyzers=True`: Runtime analyzer enabled
- `EnforceCodeStyleInBuild=True`: .NET style rules enforced
- `AnalysisLevel=6.0-recommended`: Latest analyzer rules
- `EnablePackageValidation=true`: NuGet API compatibility checks

**Key Conventions**:
1. **Strong Naming**: Assembly is signed with `KeyFile.snk` (required for NuGet package)
2. **Documentation**: All public APIs must have XML doc comments (`<summary>`, `<param>`, `<exception>`)
3. **Error Handling**: Wrap Win32 errors via `HttpApi.ThrowWin32ExceptionIfError()` → `Win32Exception`
4. **Resource Cleanup**: Use `CallHttpApi()` pattern for httpapi.dll lifecycle management

## SNI Support Refactoring (Current Focus)

**Migration Goal**: Replace raw `IPEndPoint` parameters with new `BindingEndPoint` abstraction

**Pattern Example** (`CertificateBindingConfiguration.Query()`):
```csharp
public IReadOnlyList<CertificateBinding> Query(BindingEndPoint endPoint = null)
{
    if (endPoint == null)
        return QueryMany();  // Get all bindings
    
    // Dispatch based on endpoint type (new SNI pattern)
    CertificateBinding info = endPoint.IsIpEndpoint
        ? QuerySingle(endPoint.ToIPEndPoint())
        : QuerySingle(endPoint.ToDnsEndPoint());
    return info == null ? Array.Empty<CertificateBinding>() : new[] { info };
}
```

**When Adding SNI Features**:
- Always use `BindingEndPoint` in public signatures (not raw `IPEndPoint`)
- Support both `new BindingEndPoint(IPAddress, port)` and `new BindingEndPoint(hostname, port)` constructors
- Update tests to validate DNS name bindings (use `BindingEndPointTests` as reference)

## Key Files by Purpose

| Purpose | Files |
|---------|-------|
| Public API | `CertificateBinding.cs`, `CertificateBindingConfiguration.cs`, `BindingEndPoint.cs`, `BindingOptions.cs`, `ICertificateBindingConfiguration.cs` |
| Windows Interop | `Interop/HttpApi.cs`, `Interop/BindingStructures.cs`, `Interop/SockaddrStructure.cs` |
| Validation | `ArgumentValidation.cs` |
| Tests (Core) | `CertificateBindingConfigurationTests.cs`, `BindingEndPointTests.cs`, `CertificateBindingTests.cs` |
| Tests (Helpers) | `CertConfigCmd.cs`, `ProcessExtensions.cs`, `IpEndpointTools.cs` |

## Common Pitfalls & Solutions

1. **Test Failures on Non-Admin**: Tests require elevated permissions. Run IDE/terminal as Administrator or tests will fail with access denied errors.

2. **Platform Mismatch**: Don't mix `DnsEndPoint` on .NET Framework targets without careful interop validation. `BindingEndPoint` abstracts this safely.

3. **Win32 Error Handling**: All httpapi.dll calls must check return codes and call `ThrowWin32ExceptionIfError()`. Failing to do so silently ignores binding failures.

4. **Resource Leaks**: Always use `HttpApi.CallHttpApi()` wrapper to ensure `HttpTerminate()` is called. Direct `HttpInitialize()` calls without try-finally are unsafe.

5. **Struct Marshaling**: Don't modify `BindingStructures.cs` without understanding P/Invoke layout requirements. Changes can corrupt system SSL configuration.
