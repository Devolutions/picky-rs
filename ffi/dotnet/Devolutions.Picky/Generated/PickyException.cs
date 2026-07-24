using System;

namespace Devolutions.Picky;

public class PickyException : Exception
{
    public PickyError Inner { get; }
    private readonly object[] _edges;

    public PickyException(PickyError inner, params object[] edges) : base(
        inner.ToDisplay()
    )
    {
        Inner = inner;
        _edges = edges;
    }
}