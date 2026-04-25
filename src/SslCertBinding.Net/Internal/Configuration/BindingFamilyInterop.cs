using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SslCertBinding.Net.Internal.Interop;

namespace SslCertBinding.Net.Internal
{
#if NET5_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    internal static class BindingFamilyInterop
    {
        public static void UpsertStruct<TSet>(HttpApi.HTTP_SERVICE_CONFIG_ID configId, SafeInteropResult<TSet> bindingStruct)
            where TSet : struct
        {
            try
            {
                HttpApi.CallHttpApi(
                    delegate
                    {
                        IntPtr bindingStructPtr = StructureToPtr(bindingStruct.Value);
                        try
                        {
                            int size = Marshal.SizeOf<TSet>();
                            uint retVal = HttpApi.HttpSetServiceConfiguration(
                                IntPtr.Zero,
                                configId,
                                bindingStructPtr,
                                size,
                                IntPtr.Zero);

                            if (retVal == HttpApi.ERROR_ALREADY_EXISTS)
                            {
                                retVal = HttpApi.HttpDeleteServiceConfiguration(
                                    IntPtr.Zero,
                                    configId,
                                    bindingStructPtr,
                                    size,
                                    IntPtr.Zero);
                                ThrowInteropExceptionIfNeeded(configId, retVal, treatInvalidParameterAsUnsupported: false);

                                retVal = HttpApi.HttpSetServiceConfiguration(
                                    IntPtr.Zero,
                                    configId,
                                    bindingStructPtr,
                                    size,
                                    IntPtr.Zero);
                            }

                            ThrowInteropExceptionIfNeeded(configId, retVal, treatInvalidParameterAsUnsupported: false);
                        }
                        finally
                        {
                            FreeStructurePtr<TSet>(bindingStructPtr);
                        }
                    });
            }
            finally
            {
                bindingStruct.Dispose();
            }
        }

        public static void DeleteStruct<TSet>(HttpApi.HTTP_SERVICE_CONFIG_ID configId, SafeInteropResult<TSet> bindingStruct)
            where TSet : struct
        {
            IntPtr bindingStructPtr = StructureToPtr(bindingStruct.Value);
            try
            {
                uint retVal = HttpApi.HttpDeleteServiceConfiguration(
                    IntPtr.Zero,
                    configId,
                    bindingStructPtr,
                    Marshal.SizeOf<TSet>(),
                    IntPtr.Zero);
                ThrowInteropExceptionIfNeeded(configId, retVal, treatInvalidParameterAsUnsupported: false);
            }
            finally
            {
                FreeStructurePtr<TSet>(bindingStructPtr);
                bindingStruct.Dispose();
            }
        }

        public static TBinding? QuerySingle<TQuery, TSet, TBinding>(
            HttpApi.HTTP_SERVICE_CONFIG_ID configId,
            SafeInteropResult<TQuery> queryStruct,
            Func<TSet, TBinding> mapFunc)
            where TQuery : struct
            where TSet : struct
            where TBinding : class
        {
            TBinding? result = null;

            try
            {
                HttpApi.CallHttpApi(
                    delegate
                    {
                        IntPtr queryStructPtr = StructureToPtr(queryStruct.Value);
                        IntPtr outputStructPtr = IntPtr.Zero;
                        int returnLength = 0;

                        try
                        {
                            int querySize = Marshal.SizeOf<TQuery>();
                            uint retVal = HttpApi.HttpQueryServiceConfiguration(
                                IntPtr.Zero,
                                configId,
                                queryStructPtr,
                                querySize,
                                outputStructPtr,
                                returnLength,
                                out returnLength,
                                IntPtr.Zero);

                            if (retVal == HttpApi.ERROR_FILE_NOT_FOUND)
                            {
                                return;
                            }

                            if (retVal != HttpApi.ERROR_INSUFFICIENT_BUFFER)
                            {
                                HttpApi.ThrowWin32ExceptionIfError(retVal);
                                return;
                            }

                            outputStructPtr = Marshal.AllocCoTaskMem(returnLength);
                            retVal = HttpApi.HttpQueryServiceConfiguration(
                                IntPtr.Zero,
                                configId,
                                queryStructPtr,
                                querySize,
                                outputStructPtr,
                                returnLength,
                                out returnLength,
                                IntPtr.Zero);
                            ThrowInteropExceptionIfNeeded(configId, retVal, treatInvalidParameterAsUnsupported: false);

                            TSet bindingStruct = Marshal.PtrToStructure<TSet>(outputStructPtr);
                            result = mapFunc(bindingStruct);
                        }
                        finally
                        {
                            if (outputStructPtr != IntPtr.Zero)
                            {
                                Marshal.FreeCoTaskMem(outputStructPtr);
                            }

                            FreeStructurePtr<TQuery>(queryStructPtr);
                        }
                    });
            }
            finally
            {
                queryStruct.Dispose();
            }

            return result;
        }

        public static List<TBinding> QueryMany<TQuery, TSet, TBinding>(
            HttpApi.HTTP_SERVICE_CONFIG_ID configId,
            Func<uint, TQuery> queryFactory,
            Func<TSet, TBinding> mapFunc)
            where TQuery : struct
            where TSet : struct
            where TBinding : class
        {
            var result = new List<TBinding>();

            HttpApi.CallHttpApi(
                delegate
                {
                    uint token = 0;
                    while (true)
                    {
                        TQuery queryStruct = queryFactory(token);
                        IntPtr queryStructPtr = StructureToPtr(queryStruct);
                        IntPtr outputStructPtr = IntPtr.Zero;
                        int returnLength = 0;

                        try
                        {
                            int querySize = Marshal.SizeOf(queryStruct);
                            uint retVal = HttpApi.HttpQueryServiceConfiguration(
                                IntPtr.Zero,
                                configId,
                                queryStructPtr,
                                querySize,
                                outputStructPtr,
                                returnLength,
                                out returnLength,
                                IntPtr.Zero);

                            if (retVal == HttpApi.ERROR_NO_MORE_ITEMS)
                            {
                                break;
                            }

                            if (retVal != HttpApi.ERROR_INSUFFICIENT_BUFFER)
                            {
                                HttpApi.ThrowWin32ExceptionIfError(retVal);
                            }

                            outputStructPtr = Marshal.AllocCoTaskMem(returnLength);
                            retVal = HttpApi.HttpQueryServiceConfiguration(
                                IntPtr.Zero,
                                configId,
                                queryStructPtr,
                                querySize,
                                outputStructPtr,
                                returnLength,
                                out returnLength,
                                IntPtr.Zero);
                            ThrowInteropExceptionIfNeeded(configId, retVal, treatInvalidParameterAsUnsupported: false);

                            TSet bindingStruct = Marshal.PtrToStructure<TSet>(outputStructPtr);
                            result.Add(mapFunc(bindingStruct));
                            token++;
                        }
                        finally
                        {
                            if (outputStructPtr != IntPtr.Zero)
                            {
                                Marshal.FreeCoTaskMem(outputStructPtr);
                            }

                            FreeStructurePtr<TQuery>(queryStructPtr);
                        }
                    }
                });

            return result;
        }

        public static IntPtr StructureToPtr<TStruct>(TStruct structObj)
            where TStruct : struct
        {
            IntPtr structPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<TStruct>());
            Marshal.StructureToPtr(structObj, structPtr, false);
            return structPtr;
        }

        public static void FreeStructurePtr<TStruct>(IntPtr structPtr)
            where TStruct : struct
        {
            if (structPtr == IntPtr.Zero)
            {
                return;
            }

            Marshal.DestroyStructure<TStruct>(structPtr);
            Marshal.FreeCoTaskMem(structPtr);
        }

        public static void ValidateCcsBindingOptions(BindingOptions options)
        {
            if (options != null
                && (options.DoNotVerifyCertificateRevocation
                    || options.VerifyRevocationWithCachedCertificateOnly
                    || options.EnableRevocationFreshnessTime
                    || options.NoUsageCheck
                    || options.RevocationFreshnessTime != TimeSpan.Zero
                    || options.RevocationUrlRetrievalTimeout != TimeSpan.Zero
                    || !string.IsNullOrEmpty(options.SslCtlIdentifier)
                    || !string.IsNullOrEmpty(options.SslCtlStoreName)
                    || options.NegotiateCertificate
                    || options.UseDsMappers
                    || options.DoNotPassRequestsToRawFilters
                    || options.DisableTls12))
            {
                throw new NotSupportedException("Only default BindingOptions are supported for plain CCS bindings.");
            }
        }

        public static bool ProbeSupport(
            HttpApi.HTTP_SERVICE_CONFIG_ID configId,
            SafeInteropResult<IntPtr> query,
            int querySize)
        {
            bool supported = false;

            HttpApi.CallHttpApi(
                delegate
                {
                    try
                    {
                        uint retVal = HttpApi.HttpQueryServiceConfiguration(
                            IntPtr.Zero,
                            configId,
                            query.Value,
                            querySize,
                            IntPtr.Zero,
                            0,
                            out int returnLength,
                            IntPtr.Zero);

                        supported = !IsUnsupportedBindingFamilyError(configId, retVal);
                        if (supported
                            && retVal != HttpApi.ERROR_NO_MORE_ITEMS
                            && retVal != HttpApi.ERROR_INSUFFICIENT_BUFFER)
                        {
                            HttpApi.ThrowWin32ExceptionIfError(retVal);
                        }
                    }
                    finally
                    {
                        query.Dispose();
                    }
                });

            return supported;
        }

        public static void ThrowInteropExceptionIfNeeded(
            HttpApi.HTTP_SERVICE_CONFIG_ID configId,
            uint retVal,
            bool treatInvalidParameterAsUnsupported)
        {
            if (treatInvalidParameterAsUnsupported && IsUnsupportedBindingFamilyError(configId, retVal))
            {
                throw CreateBindingFamilyPlatformNotSupportedException(configId);
            }

            HttpApi.ThrowWin32ExceptionIfError(retVal);
        }

        private static bool IsUnsupportedBindingFamilyError(HttpApi.HTTP_SERVICE_CONFIG_ID configId, uint retVal)
        {
            return retVal == HttpApi.ERROR_INVALID_PARAMETER
                && (configId == HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo
                    || configId == HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslCcsCertInfo
                    || configId == HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslScopedCcsCertInfo);
        }

        private static PlatformNotSupportedException CreateBindingFamilyPlatformNotSupportedException(HttpApi.HTTP_SERVICE_CONFIG_ID configId) =>
            configId switch
            {
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslSniCertInfo => new("Hostname-based SSL bindings (SNI) are not supported on this version of Windows."),
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslCcsCertInfo => new("Central certificate store SSL bindings (CCS) are not supported on this version of Windows."),
                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSslScopedCcsCertInfo => new("Scoped central certificate store SSL bindings are not supported on this version of Windows."),
                _ => new("The requested SSL binding family is not supported on this version of Windows."),
            };
    }
}
