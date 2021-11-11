namespace Devolutions.Picky;

public class ErrorException : System.Exception
{
    public ErrorException(String message) : base(message) { }
}

public static class Error
{
    /// <summary>Returns a String containing last error message from Picky.</summary>
    public static String Last()
    {
        int len = Native.Raw.last_error_length_utf8();

        if (len == 0)
        {
            throw new ErrorException("no error message to retrieve from Picky");
        }

        byte[] buf = new byte[len];

        unsafe
        {
            fixed (byte* bufPtr = buf)
            {
                int ret = Native.Raw.error_message_utf8((sbyte*)bufPtr, buf.Length);

                if (ret == -1)
                {
                    throw new ErrorException("failed to read last Picky error");
                }

                Native.Raw.clear_last_error();

                return Utils.Utf8WithNulTerminatorToString(buf);
            }
        }
    }
}