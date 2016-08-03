using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace TorNet
{
    internal class TcpSocket : Stream
    {
        public string Host
        {
            get { return _host; }
        }

        public IPAddress IPAddress
        {
            get { return _ip; }
        }

        public ushort Port
        {
            get { return _port; }
        }

        public bool IsConnected
        {
            get { return _socket != null; }
        }

        public TcpSocket()
        {
            return;
        }

        public TcpSocket(string host, ushort port)
        {
            Connect(host, port);
        }

        ~TcpSocket()
        {
            Close();
        }

        public void Connect(string host, ushort port)
        {
            // TODO : ONce connected to the first node, avoid using regular DNS queries.
            IPHostEntry h = Dns.GetHostByName(host);
            _ip = h.AddressList[0];
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try {
                _socket.Connect(new IPEndPoint(_ip, port));
                return;
            }
            catch {
                _socket.Close();
                throw;
            }
        }

        public override void Close()
        {
            _socket.Close();
            _socket = null;
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _socket.Receive(buffer, count, 0);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _socket.Send(buffer, count, 0);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
            return;
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        private string _host;
        private IPAddress _ip;
        private Socket _socket;
        private ushort _port;
    }
}
