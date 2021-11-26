namespace Devolutions.Picky;

public static class Hash
{
    public static byte[] Digest(this HashAlgorithm algorithm, byte[] message)
    {
        unsafe
        {
            int len = Native.Raw.digest_length((int)algorithm);

            if (len == -1)
            {
                throw new HashException(Error.Last());
            }

            byte[] output = new byte[len];

            fixed (byte* messagePtr = message, outputPtr = output)
            {
                if (Native.Raw.digest((int)algorithm, messagePtr, message.Length, outputPtr, output.Length) == Native.picky_status_t.PICKY_STATUS_FAILURE)
                {
                    throw new HashException(Error.Last());
                }
            }

            return output;
        }
    }
}
