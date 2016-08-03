using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TorNet
{
    internal class Logger
    {
        private Logger()
        {
            return;
        }

        internal Level LogLevel
        {
            get { return _level; }
            set { _level = value; }
        }

        internal void Log(Level l, string format, params object[] args)
        {
            if (l >= _level) {
                WriteWithColorArgs(_levelColors[(int)l], format, args);
            }
        }

        internal static void Debug(string format, params object[] args)
        {
            _instance.Log(Level.debug, format, args);
        }

        internal static void Error(string format, params object[] args)
        {
            _instance.Log(Level.error, format, args);
        }

        internal static void Info(string format, params object[] args)
        {
            _instance.Log(Level.info, format, args);
        }

        internal static void Warning(string format, params object[] args)
        {
            _instance.Log(Level.warning, format, args);
        }

        private static void WriteWithColorArgs(ConsoleColor color, string format, params object[] args)
        {
            lock (_consoleLock) {
                ConsoleColor previousColor = Console.ForegroundColor;
                Console.ForegroundColor = color;
                try { Console.Write(format, args); }
                finally { Console.ForegroundColor = previousColor; }
            }
        }

        private static object _consoleLock = new object();
        private static Logger _instance = new Logger();
        private Level _level = Level.info;
        private static readonly ConsoleColor[] _levelColors = new ConsoleColor[] {
            ConsoleColor.Green , // debug
            ConsoleColor.Green, // info
            ConsoleColor.Magenta, // warning
            ConsoleColor.Red, // error
        };

        internal enum Level
        {
            debug,
            info,
            warning,
            error,
            off,
        }
    }
}