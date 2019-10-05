using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution.Injection
{
    //Used to provide/enforce properties of Variants
    //Each type of technique defines a strategy interface
    //Each variant should both inherit from VariantType && implement the specific strategy interface for their technique
    public interface IRemoteThreadInjectionStrategy
    {
        RemoteThreadOptions options { get; set; }
    }

    /// <summary>
    /// Struct containing a set of options for all Remote Thread Variants.
    /// </summary>
    public struct RemoteThreadOptions
    {
        //Whether or not to create the thread in a suspended state.
        public bool suspended;

        /// <summary>
        /// Constructor for options struct.
        /// </summary>
        /// <param name="suspendOption">Whether or not to create the thread in a suspended state.</param>
        public RemoteThreadOptions(bool suspendOption)
        {
            suspended = suspendOption;
        }
    }

    //We deviate slightly from the typical Strategy design pattern in that we use an abstract class instead of an interface for our algorithm.
    //this is because the 

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
    //      Variants should each inherit from the appropriate interface to receive the options and attributes unique the injection strategy

    //In the Strategy design pattern, this is the client.
    //The Inject method takes as an argument something that implements IRemoteThreadInjectionStrategy

    /// <summary>
    /// 
    /// </summary>
    public class RemoteThreadInjector : InjectionType
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
