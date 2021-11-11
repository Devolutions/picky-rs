namespace Devolutions.Picky;

public class PemException : System.Exception
{
    public PemException(String message) : base(message) { }
}

public class Pem
{
    private unsafe Native.picky_pem_t* inner = null;

    private String? label = null;

    public String Label
    {
        get
        {
            return this.GetLabel();
        }
    }

    private byte[]? data = null;

    public byte[] Data
    {
        get
        {
            return this.GetData();
        }
    }

    public Pem(String label, byte[] data)
    {
        byte[] utf8Label = Utils.StringToUtf8WithNulTerminator(label);

        unsafe
        {
            fixed (byte* utf8LabelPtr = utf8Label, dataPtr = data)
            {
                this.inner = Native.Raw.pem_new((sbyte*)utf8LabelPtr, utf8Label.Length, dataPtr, data.Length);

                if (this.inner == null)
                {
                    throw new PemException(Error.Last());
                }

                this.label = label;
                this.data = data;
            }
        }
    }

    public Pem(String pem_repr)
    {
        byte[] input = Utils.StringToUtf8WithNulTerminator(pem_repr);

        unsafe
        {
            // Pin the buffer to a fixed location in memory so that garbage collector
            // don't move it while it's being used inside the native call.
            fixed (byte* inputPtr = input)
            {
                this.inner = Native.Raw.pem_parse((sbyte*)inputPtr, input.Length);

                if (this.inner == null)
                {
                    throw new PemException(Error.Last());
                }
            }
        }
    }

    public String ToRepr()
    {
        unsafe
        {
            int len = Native.Raw.pem_compute_repr_length(this.inner);

            if (len == -1)
            {
                throw new PemException(Error.Last());
            }

            byte[] buf = new byte[len];

            fixed (byte* bufPtr = buf)
            {
                if (Native.Raw.pem_to_repr(this.inner, (sbyte*)bufPtr, buf.Length) != len)
                {
                    throw new PemException(Error.Last());
                }
            }

            return Utils.Utf8WithNulTerminatorToString(buf);
        }
    }

    public String GetLabel()
    {
        if (this.label != null)
        {
            return this.label;
        }

        unsafe
        {
            int len = Native.Raw.pem_label_length(this.inner);

            if (len == -1)
            {
                throw new PemException(Error.Last());
            }

            byte[] buf = new byte[len];

            fixed (byte* bufPtr = buf)
            {
                if (Native.Raw.pem_label(this.inner, (sbyte*)bufPtr, buf.Length) != len)
                {
                    throw new PemException(Error.Last());
                }
            }

            this.label = Utils.Utf8WithNulTerminatorToString(buf);

            return this.label;
        }
    }

    public byte[] GetData()
    {
        if (this.data != null)
        {
            return this.data;
        }

        unsafe
        {
            int len = Native.Raw.pem_data_length(this.inner);

            if (len == -1)
            {
                throw new PemException(Error.Last());
            }

            byte[] buf = new byte[len];

            fixed (byte* bufPtr = buf)
            {
                if (Native.Raw.pem_data(this.inner, bufPtr, buf.Length) != len)
                {
                    throw new PemException(Error.Last());
                }
            }

            this.data = buf;

            return buf;
        }
    }

    ~Pem()
    {
        unsafe
        {
            Native.Raw.pem_drop(this.inner);
            this.inner = null;
        }
    }
}