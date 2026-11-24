using System;
using Devolutions.Picky;

// oracle: spec RFC 7468 §3
Pem pem = Pem.Parse("-----BEGIN TEST-----\nAQID\n-----END TEST-----");
if (pem.Label != "TEST" || !pem.ToData().AsSpan().SequenceEqual(new byte[] { 1, 2, 3 }))
{
    throw new Exception("Native PEM parsing returned unexpected data.");
}

Console.WriteLine("Native PEM parsing succeeded.");
