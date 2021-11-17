using System.Text;

namespace Devolutions.Picky;

public static class Utils
{
    public static byte[] StringToUtf8WithNulTerminator(string s)
    {
        int size = Encoding.UTF8.GetByteCount(s) + 1;
        byte[] buf = new byte[size];
        Encoding.UTF8.GetBytes(s, 0, s.Length, buf, 0);
        buf[size - 1] = 0; // make sure we have a C-style nul-byte
        return buf;
    }

    public static string Utf8WithNulTerminatorToString(byte[] utf8)
    {
        int sizeWithoutNul = utf8.Length - 1;
        char[] chars = new char[sizeWithoutNul];
        Encoding.UTF8.GetChars(utf8, 0, sizeWithoutNul, chars, 0);
        return new string(chars);
    }
}