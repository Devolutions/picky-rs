using System.Text;

namespace Devolutions.Picky;

public static class Utils
{
    public static byte[] StringToUtf8WithNulTerminator(String s)
    {
        int size = Encoding.UTF8.GetByteCount(s) + 1;
        byte[] buf = new byte[size];
        Encoding.UTF8.GetBytes(s, 0, s.Length, buf, 0);
        buf[size - 1] = 0; // make sure we have a C-style nul-byte
        return buf;
    }

    public static String Utf8WithNulTerminatorToString(byte[] utf8)
    {
        int size_without_nul = utf8.Length - 1;
        char[] chars = new char[size_without_nul];
        Encoding.UTF8.GetChars(utf8, 0, size_without_nul, chars, 0);
        return new String(chars);
    }
}