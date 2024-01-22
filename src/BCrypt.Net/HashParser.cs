using System;

namespace BCrypt.Net
{
    internal static class HashParser
    {
        private static readonly HashFormatDescriptor OldFormatDescriptor = new HashFormatDescriptor(versionLength: 1);
        private static readonly HashFormatDescriptor NewFormatDescriptor = new HashFormatDescriptor(versionLength: 2);

        internal static HashInformation GetHashInformation(string hash)
        {
            if (!IsValidHash(hash, out var format))
            {
                ThrowInvalidHashFormat();
            }

            return new HashInformation(
                hash.Substring(0, format.SettingLength),
                hash.Substring(1, format.VersionLength),
                hash.Substring(format.WorkfactorOffset, 2),
                hash.Substring(format.HashOffset));
        }

#if HAS_SPAN
        internal static HashInformation GetHashInformation(ReadOnlySpan<char> hash)
        {
            if (!IsValidHash(hash, out var format))
            {
                ThrowInvalidHashFormat();
            }

            return new HashInformation(
                hash.Slice(0, format.SettingLength).ToString(),
                hash.Slice(1, format.VersionLength).ToString(),
                hash.Slice(format.WorkfactorOffset, 2).ToString(),
                hash.Slice(format.HashOffset).ToString());
        }
#endif

        internal static int GetWorkFactor(
#if HAS_SPAN
            ReadOnlySpan<char> hash)
#else
            string hash)
#endif
        {
            if (!IsValidHash(hash, out var format))
            {
                ThrowInvalidHashFormat();
            }

            int offset = format.WorkfactorOffset;

            return 10 * (hash[offset] - '0') + (hash[offset + 1] - '0');
        }

        internal static bool IsValidHash(string hash,
#if HAS_SPAN
            out HashFormatDescriptor format)
        {
            return IsValidHash(hash.AsSpan(), out format);
        }

        internal static bool IsValidHash(
            ReadOnlySpan<char> hash,
#endif
            out HashFormatDescriptor format)
        {
            if (hash.Length != 59 && hash.Length != 60)
            {
                // Incorrect full hash length
                format = HashFormatDescriptor.Empty;
                return false;
            }

            if (!hash.StartsWith("$2"))
            {
                // Not a bcrypt hash
                format = HashFormatDescriptor.Empty;
                return false;
            }

            // Validate version
            int offset = 2;
            if (IsValidBCryptVersionChar(hash[offset]))
            {
                offset++;
                format = NewFormatDescriptor;
            }
            else
            {
                format = OldFormatDescriptor;
            }

            if (hash[offset++] != '$')
            {
                format = HashFormatDescriptor.Empty;
                return false;
            }

            // Validate workfactor
            if (!IsAsciiNumeric(hash[offset++])
                || !IsAsciiNumeric(hash[offset++]))
            {
                format = HashFormatDescriptor.Empty;
                return false;
            }

            if (hash[offset++] != '$')
            {
                format = HashFormatDescriptor.Empty;
                return false;
            }

            // Validate hash
            for (int i = offset; i < hash.Length; ++i)
            {
                if (!IsValidBCryptBase64Char(hash[i]))
                {
                    format = HashFormatDescriptor.Empty;
                    return false;
                }
            }

            return !format.IsEmpty;
        }

        private static bool IsValidBCryptVersionChar(char value)
        {
            return value == 'a'
                   || value == 'b'
                   || value == 'x'
                   || value == 'y';
        }

        private static bool IsValidBCryptBase64Char(char value)
        {
            // Ordered by ascending ASCII value
            return value == '.'
                   || value == '/'
                   || (value >= '0' && value <= '9')
                   || (value >= 'A' && value <= 'Z')
                   || (value >= 'a' && value <= 'z');
        }

        private static bool IsAsciiNumeric(char value)
        {
            return value >= '0' && value <= '9';
        }

        private static void ThrowInvalidHashFormat()
        {
            throw new SaltParseException("Invalid Hash Format");
        }

        internal readonly struct HashFormatDescriptor
        {
            internal HashFormatDescriptor(int versionLength)
            {
                int workfactorOffset = 1 + versionLength + 1;
                int settingLength = workfactorOffset + 2;

                VersionLength = versionLength;
                WorkfactorOffset = workfactorOffset;
                SettingLength = settingLength;
                HashOffset = settingLength + 1;
                _isNotEmpty = true;
            }
            private HashFormatDescriptor(bool empty)
            {
                _isNotEmpty = !empty;
                VersionLength = 0;
                WorkfactorOffset = 0;
                SettingLength = 0;
                HashOffset = 0;
            }

            private readonly bool _isNotEmpty;

            internal bool IsEmpty => !_isNotEmpty;

            internal readonly int VersionLength;

            internal readonly int WorkfactorOffset;

            internal readonly int SettingLength;

            internal readonly int HashOffset;

            internal static readonly HashFormatDescriptor Empty = new HashFormatDescriptor(empty: true);
        }
    }
}
