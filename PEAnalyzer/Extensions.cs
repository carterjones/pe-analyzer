namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// A collection of miscellaneous extension methods.
    /// </summary>
    internal static class Extensions
    {
        /// <summary>
        /// Get a hexidecimal address representation of a 32-bit address value.
        /// </summary>
        /// <param name="value">the address value</param>
        /// <returns>a hexidecimal address representation of a 32-bit address value</returns>
        public static string ToAddressString32(this ulong value)
        {
            return "0x" + new IntPtr((long)value).ToString("x").PadLeft(8, '0');
        }

        /// <summary>
        /// Get a hexidecimal address representation of a 64-bit address value.
        /// </summary>
        /// <param name="value">the address value</param>
        /// <returns>a hexidecimal address representation of a 64-bit address value</returns>
        public static string ToAddressString64(this ulong value)
        {
            return "0x" + new IntPtr((long)value).ToString("x").PadLeft(16, '0');
        }
    }
}
