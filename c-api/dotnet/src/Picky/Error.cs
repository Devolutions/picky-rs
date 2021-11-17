namespace Devolutions.Picky;

public static class Error
{
    /// <summary>
    /// Returns a string containing last error message from Picky.
    ///
    /// When calling native functions, user is supposed to check if that
    /// function returned a special value (null, -1…) and only then call
    /// this function to retrieve the error description.
    /// This function fails (intentionally) if no error occurred in native code.
    ///
    /// Users of idiomatic C# wrappers are not expected to use this interface.
    /// </summary>
    public static string Last()
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