using System;
using System.Diagnostics;

namespace Devolutions.Picky.Native
{
    /// <summary>Defines the vtbl index of a method as it was in the native signature.</summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    [Conditional("DEBUG")]
    internal sealed partial class VtblIndexAttribute : Attribute
    {
        private readonly uint _index;

        /// <summary>Initializes a new instance of the <see cref="VtblIndexAttribute" /> class.</summary>
        /// <param name="index">The vtbl index of a method as it was in the native signature.</param>
        public VtblIndexAttribute(uint index)
        {
            _index = index;
        }

        /// <summary>Gets the vtbl index of a method as it was in the native signature.</summary>
        public uint Index => _index;
    }
}