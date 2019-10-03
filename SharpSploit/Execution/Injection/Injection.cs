using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for Injection strategies.
    /// </summary>
    public abstract class InjectionType
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="variant"></param>
        /// <param name="payload"></param>
        /// <param name="alloc"></param>
        /// <param name="process"></param>
        /// <returns></returns>
        abstract public bool Inject(VariantType variant, PayloadType payload, AllocationType alloc, System.Diagnostics.Process process);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="variant"></param>
        /// <param name="payload"></param>
        /// <param name="baseAddr"></param>
        /// <param name="process"></param>
        /// <returns></returns>
        abstract public bool Inject(VariantType variant, PayloadType payload, IntPtr baseAddr, System.Diagnostics.Process process);
    }


    //TODO: What is the purpose of this Injection class?
    //      It should be to provide options universal to the strategy. Variant-specifc options can be passed to them.

    /// <summary>
    /// 
    /// </summary>
    public class RemoteThreadInject : InjectionType
    {
        public override bool Inject(VariantType variant, PayloadType payload, AllocationType alloc, System.Diagnostics.Process process)
        {
            bool success = false;



            return success;
        }

        public override bool Inject(VariantType variant, PayloadType payload, IntPtr baseAddr, System.Diagnostics.Process process)
        {
            return variant.Inject(payload, baseAddr, process);
        }
    }
}
