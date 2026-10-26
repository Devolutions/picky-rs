using System;

namespace Devolutions.Picky;

/// <summary>
/// If <c>BufferTooSmallError</c> is an opaque error that borrows from an opaque
/// parameter or the receiver, that source handle is held by <c>Inner</c>'s
/// managed lifetime edge rather than by this exception class.
/// </summary>
public class BufferTooSmallException : Exception
{
    public BufferTooSmallError Inner { get; }

    public BufferTooSmallException(BufferTooSmallError inner) : base(
        inner.ToDisplay()
    )
    {
        Inner = inner;
    }
}