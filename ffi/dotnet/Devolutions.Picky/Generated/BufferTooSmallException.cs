using System;

namespace Devolutions.Picky;

public class BufferTooSmallException : Exception
{
    public BufferTooSmallError Inner { get; }
    private readonly object[] _edges;

    public BufferTooSmallException(BufferTooSmallError inner, params object[] edges) : base(
        inner.ToDisplay()
    )
    {
        Inner = inner;
        _edges = edges;
    }
}