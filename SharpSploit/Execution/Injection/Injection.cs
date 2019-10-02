using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution.Injection
{
    interface IInjection
    {
        bool Inject(VariantType variant, PayloadType payload, IntPtr baseAddr, System.Diagnostics.Process process);
    }
}
