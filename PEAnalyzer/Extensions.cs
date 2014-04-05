namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    internal static class Extensions
    {
        public static string ToAddressString32(this ulong value)
        {
            return "0x" + new IntPtr((long)value).ToString("x").PadLeft(8, '0');
        }

        public static string ToAddressString64(this ulong value)
        {
            return "0x" + new IntPtr((long)value).ToString("x").PadLeft(16, '0');
        }
    }
}
