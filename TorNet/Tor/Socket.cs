using System;
using System.Collections.Generic;
using System.Net;

namespace TorNet.Tor
{
    internal class Socket
    {
        internal Socket()
        {
            return;
        }

        internal Socket(OnionRouter first_hop)
        {
            _first_hop = first_hop;
            _protocol_version = 3;
            Connect(first_hop.IPAddress, first_hop.ORPort);
        }

        internal uint ProtocolVersion
        {
            get { return _protocol_version; }
        }

        internal void Connect(IPAddress ip, ushort port)
        {
            _socket.Connect(ip.ToString(), port);
            SendCell(new Cell(0, CellCommand.versions, new byte[] { 0, 3, 0, 4 }));
            Cell version_reply = recv_cell();

            for (int i = 0; i < version_reply.Payload.Length; i += 2) {
                ushort offered_version = (ushort)(version_reply.Payload[i] + (256 * version_reply.Payload[i + 1]));
                offered_version = offered_version.SwapEndianness();
                if (   (offered_version <= protocol_version_max)
                    && (offered_version > _protocol_version))
                {
                    _protocol_version = offered_version;
                }
            }
        }

        private void SendCell(Cell c)
        {
            Console.WriteLine(
                ">> send_cell [circ_id: {0}, cmd_id: {1}]\n", c.CircuitId, c.Command);
            byte[] cell_content = c.GetBytes((ushort)_protocol_version);
            _socket.Write(cell_content, cell_content.Length);
        }

        private Cell recv_cell()
        {
            Cell result = new Cell();
            byte[] header = new byte[5];
            _socket.Read(header, _protocol_version == 3 ? 3 : 5);

            if (_protocol_version < 4) {
                result.CircuitId = header.SwapEndianness().ToUInt16();
            }
            else {
                result.CircuitId = header.SwapEndianness().ToUInt32();
            }
            result.Command = (CellCommand)header[_protocol_version < 4 ? 2 : 4];
            int payload_length = 509;
            if (result.Command ==CellCommand.versions || (uint)result.Command >= 128) {
                byte[] localBuffer = new byte[2];
                _socket.Read(localBuffer, localBuffer.Length);
                payload_length = localBuffer.ToUInt16();
                payload_length = ((ushort)payload_length).SwapEndianness();
            }
            result.ResizePayload(payload_length);
            _socket.Read(result.Payload, payload_length);
            Console.WriteLine("<< recv_cell [circ_id: {0}, cmd_id: {1}]\n",
                result.CircuitId, result.Command);
            return result;
        }

        private void send_net_info()
        {
            // byte[] nibuf = new byte[4 + 2 + 4 + 3 + 4];
            List<byte> nibuf = new List<byte>();
            byte[] remote = _socket.UnderlyingSocket.IPAddress.GetAddressBytes();
            if (4 != remote.Length) {
                throw new NotSupportedException();
            }
            uint local = 0xC0A80016;
            uint epoch = (uint)DateTime.Now.SecondsSinceEpoch();

            nibuf.AddRange(epoch.ToArray().SwapEndianness());
            nibuf.Add(0x04);
            nibuf.Add(0x04);
            nibuf.AddRange(remote.SwapEndianness());
            nibuf.Add(0x01);
            nibuf.Add(0x04);
            nibuf.Add(0x04);
            nibuf.AddRange(local.ToArray().SwapEndianness());
            SendCell(new Cell(0, CellCommand.netinfo, nibuf.ToArray()));
            return;
        }

        private void recv_certificates(Cell c)
        {
            int certificate_count = c.Payload[0];
        }

        private void receive_handler_loop()
        {
            for (;;) {
                Cell c = recv_cell();
                switch (c.Command) {
                    case CellCommand.netinfo:
                        send_net_info();
                        set_state(state.ready);
                        break;
                    case CellCommand.certs:
                        recv_certificates(c);
                        break;
                    default:
                        //circuit circ = 
                        break;
                }
            }
        }

        private void set_state(state new_state)
        {
            _state = new_state;
        }

        private string fetch_hs_descriptor(string onion)
        {
            return string.Empty;
        }

        public const ushort protocol_version_max = 4;
        private SslSocket _socket;
        private OnionRouter _first_hop;
        private uint _protocol_version;
        private state _state;

        public enum state
        {
            initialising,
            ready
        }
    }
}
