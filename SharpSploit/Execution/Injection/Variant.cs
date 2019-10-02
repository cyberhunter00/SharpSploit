using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for injection strategies (variants).
    /// </summary>
    abstract class VariantType
    {
        //An array containing a set of PayloadType objects that are supported.
        Type[] supportedPayloads = null;

        /// <summary>
        /// Informs objects using this strategy whether or not it supports the type of a particular payload.
        /// </summary>
        /// <param name="payload">A payload.</param>
        /// <returns>Whether or not the payload is of a supported type for this strategy.</returns>
        public bool IsSupportedPayloadType(PayloadType payload)
        {
            return supportedPayloads.Contains(payload.GetType());
        }

        /// <summary>
        /// Top-level method for injecting payloads using this strategy.
        /// This wrapper function should invoke the Inject method for the appropriate payload type and 
        ///     return a PayloadTypeNotSupported exception if the payload passed in is not supported.
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="baseAddr"></param>
        /// <param name="process"></param>
        /// <returns></returns>
        abstract public bool Inject(PayloadType payload, IntPtr baseAddr, System.Diagnostics.Process process);
    }


}
