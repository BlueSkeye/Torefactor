using System;

namespace TorNet
{
    internal class ParsingException : ApplicationException
    {
        internal ParsingException()
        {
        }

        internal ParsingException(string message, params object[] args)
            : base(FormatMessage(message, args))
        {
        }

        private static string FormatMessage(string message, params object[] args)
        {
            try { return string.Format(message, args); }
            catch { return message ?? "NULL MESSAGE"; }
        }
    }
}
