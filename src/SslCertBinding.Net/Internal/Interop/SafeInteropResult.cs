using System;

namespace SslCertBinding.Net.Internal.Interop
{
    /// <summary>
    /// Holds a native interop structure together with the managed cleanup actions
    /// needed after the structure has been consumed by the Win32 API.
    /// </summary>
    internal sealed class SafeInteropResult<T> : IDisposable
        where T : struct
    {
        private readonly Action[] _disposeActions;
        private bool _disposed;

        public SafeInteropResult(T value, params Action[] disposeActions)
        {
            Value = value;
            _disposeActions = disposeActions ?? Array.Empty<Action>();
        }

        public T Value { get; }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            foreach (Action disposeAction in _disposeActions)
            {
                disposeAction?.Invoke();
            }

            _disposed = true;
        }
    }
}
