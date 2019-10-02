﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for all types of payloads.
    /// Variants are responsible for specifying what types of payloads they support.
    /// </summary>
    public abstract class PayloadType
    {
        //Byte array containing the payload.
        private byte[] payload;
        public byte[] Payload
        {
            get
            {
                return payload;
            }
        }

        //Constructor that requires the user pass in the payload as a byte array.
        protected PayloadType(byte[] data)
        {
            payload = data;
        }
    }

    /// <summary>
    /// Represents payloads that are position-independant-code.
    /// </summary>
    public class PICPayload : PayloadType
    {
        //Declares the constructor as equivalent to that of the base class.
        public PICPayload(byte[] data) : base(data)
        { }
    }

    /// <summary>
    /// Exception thrown when a the type of a payload is not supported by a injection variant.
    /// </summary>
    public class PayloadTypeNotSupported : Exception
    {
        public PayloadTypeNotSupported()
        { }

        public PayloadTypeNotSupported(Type payloadType) : base(String.Format("Unsupported Payload type: {0}", payloadType.Name))
        { }
    }
}
