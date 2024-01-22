using System;
using System.Collections.Generic;
using System.Text;

namespace BCrypt.Net
{
    internal static class SpanExtensions
    {
#if HAS_SPAN
        internal static bool StartsWith(this ReadOnlySpan<char> span, string str)
        {
            return span.StartsWith(str.AsSpan());
        }
#endif
    }
}

