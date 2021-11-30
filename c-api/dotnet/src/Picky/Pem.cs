namespace Devolutions.Picky;

public class Pem
{
    private unsafe Native.picky_pem_t* _inner = null;
    private string? _label = null;
    private byte[]? _data = null;

    public string Label
    {
        get
        {
            return GetLabel();
        }
    }

    public byte[] Data
    {
        get
        {
            return GetData();
        }
    }

    public Pem(string label, byte[] data)
    {
        byte[] utf8Label = Utils.StringToUtf8WithNulTerminator(label);

        unsafe
        {
            fixed (byte* utf8LabelPtr = utf8Label, dataPtr = data)
            {
                _inner = Native.Raw.pem_new((sbyte*)utf8LabelPtr, utf8Label.Length, dataPtr, data.Length);

                if (_inner == null)
                {
                    throw new PemException(Error.Last());
                }

                _label = label;
                _data = data;
            }
        }
    }

    public Pem(string pem_repr)
    {
        byte[] input = Utils.StringToUtf8WithNulTerminator(pem_repr);

        unsafe
        {
            // Pin the buffer to a fixed location in memory so that garbage collector
            // don't move it while it's being used inside the native call.
            fixed (byte* inputPtr = input)
            {
                _inner = Native.Raw.pem_parse((sbyte*)inputPtr, input.Length);

                if (_inner == null)
                {
                    throw new PemException(Error.Last());
                }
            }
        }
    }

    public string ToRepr()
    {
        unsafe
        {
            int len = Native.Raw.pem_compute_repr_length(_inner);

            if (len == -1)
            {
                throw new PemException(Error.Last());
            }

            byte[] buf = new byte[len];

            fixed (byte* bufPtr = buf)
            {
                if (Native.Raw.pem_to_repr(_inner, (sbyte*)bufPtr, buf.Length) != len)
                {
                    throw new PemException(Error.Last());
                }
            }

            return Utils.Utf8WithNulTerminatorToString(buf);
        }
    }

    public string GetLabel()
    {
        if (_label != null)
        {
            return _label;
        }

        unsafe
        {
            int len = Native.Raw.pem_label_length(_inner);

            if (len == -1)
            {
                throw new PemException(Error.Last());
            }

            byte[] buf = new byte[len];

            fixed (byte* bufPtr = buf)
            {
                if (Native.Raw.pem_label(_inner, (sbyte*)bufPtr, buf.Length) != len)
                {
                    throw new PemException(Error.Last());
                }
            }

            _label = Utils.Utf8WithNulTerminatorToString(buf);

            return _label;
        }
    }

    public byte[] GetData()
    {
        if (_data != null)
        {
            return _data;
        }

        unsafe
        {
            int len = Native.Raw.pem_data_length(_inner);

            if (len == -1)
            {
                throw new PemException(Error.Last());
            }

            byte[] buf = new byte[len];

            fixed (byte* bufPtr = buf)
            {
                if (Native.Raw.pem_data(_inner, bufPtr, buf.Length) != len)
                {
                    throw new PemException(Error.Last());
                }
            }

            _data = buf;

            return buf;
        }
    }

    ~Pem()
    {
        unsafe
        {
            Native.Raw.pem_drop(_inner);
            _inner = null;
        }
    }
}
