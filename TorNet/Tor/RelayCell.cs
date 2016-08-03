using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using TorNet.IO;

namespace TorNet.Tor
{
    internal class RelayCell : Cell
    {
        public RelayCell()
            : base()
        {
            return;
        }

        public RelayCell(CircuitNode node, Cell cell)
            : base(ref cell)
        {
            _circuit_node = node;
            MemoryStream payload_stream = new MemoryStream(cell.Payload);
            StreamWrapper payload_buffer = new StreamWrapper(payload_stream, Endianness.big_endian);
            CellCommand relay_command = (CellCommand)payload_buffer.ReadByte();
            ushort dummy = payload_buffer.ReadUInt16();
            ushort stream_id = payload_buffer.ReadUInt16();
            uint digest = payload_buffer.ReadUInt32();
            ushort payload_size = payload_buffer.ReadUInt16();

            byte[] payload = new byte[payload_size];
            payload_buffer.Read(payload);
            _relay_command = relay_command;
            _stream_id = stream_id;
            this.RelayPayload = payload;
        }

        public RelayCell(uint circuit_id, CellCommand command, CircuitNode node,
            CellCommand relay_command, ushort stream_id, byte[] relay_payload)
            : base(circuit_id, command)
        {
            // : cell(circuit_id, command)
            _circuit_node = node;
            _relay_command = relay_command;
            _stream_id = stream_id;
            this.RelayPayload = relay_payload;
        }

        public ushort StreamId
        {
            get { return _stream_id; }
        }

        public TorStream Stream
        {
            get { return _circuit_node.Circuit.GetStreamById(_stream_id); }
        }

        public CellCommand RelayCommand
        {
            get { return _relay_command; }
        }

        public CircuitNode CircuitNode
        {
            get { return _circuit_node; }
        }

        public void SetDigest(byte[] digest)
        {
            Buffer.BlockCopy(digest, 0, _digest, 0, digest.Length);
        }

        public byte[] RelayPayload
        {
            get { return _relay_payload; }
            set { _relay_payload = value; }
        }

        public bool IsRelayCellValid
        {
          // each valid relay cell has set its circuit node.
            get { return (null != _circuit_node); }
        }

        private CircuitNode _circuit_node;
        private CellCommand _relay_command = 0;
        private ushort _stream_id = 0;
        private byte[] _digest = new byte[4];
        private byte[] _relay_payload;
    }
}
