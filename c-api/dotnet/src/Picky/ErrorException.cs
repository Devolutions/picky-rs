namespace Devolutions.Picky;

public class ErrorException : System.Exception
{
    public ErrorException(string message) : base(message) { }
}