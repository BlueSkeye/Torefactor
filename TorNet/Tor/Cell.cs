using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using TorNet.IO;

namespace TorNet.Tor
{
    internal class Cell
    {
        internal Cell()
        {
            return;
        }

        internal Cell(ref Cell other)
        {
            Swap(ref other);
        }

        internal Cell(uint circuit_id, CellCommand command, byte[] payload = null)
        {
            this._circuit_id = circuit_id;
            this._command = command;
            this._payload = payload;
        }

        private void Swap(ref Cell other)
        {
            Helpers.Swap(ref _circuit_id, ref other._circuit_id);
            Helpers.Swap(ref _command, ref other._command);
            Helpers.Swap(ref _payload, ref other._payload);
        }

        internal uint CircuitId
        {
            get { return _circuit_id; }
            set { _circuit_id = value; }
        }

        internal CellCommand Command
        {
            get { return _command; }
            set { _command = value; }
        }

        internal bool IsValid
        {
            get { return _is_valid; }
        }

        internal byte[] Payload
        {
            get { return _payload; }
            set { _payload = value; }
        }

        internal byte[] GetBytes(ushort protocol_version)
        {
            byte[] cell_bytes;

            if (_command == CellCommand.versions || (uint)_command >= 128) {
                cell_bytes = new byte[
                      // circuit id.
                      (protocol_version < 4 ? sizeof(ushort) : sizeof(uint)) +
                      // cell command.
                      sizeof(CellCommand) +
                      // payload size (16 bits).
                      sizeof(ushort) +
                      // payload.
                      _payload.Length];
            }
            else { cell_bytes = new byte[514]; }
            MemoryStream cell_stream = new MemoryStream(cell_bytes);
            StreamWrapper cell_buffer = new StreamWrapper(cell_stream, Endianness.big_endian);

            // tor-spec.txt
            // 5.1.1.
            // In link protocol 3 or lower, CircIDs are 2 bytes long;
            // in protocol 4 or higher, CircIDs are 4 bytes long.
            if (4 > protocol_version) {
                cell_buffer.Write((ushort)_circuit_id);
            }
            else { cell_buffer.Write((uint)_circuit_id); }
            cell_buffer.Write((byte)_command);
            if (_command == CellCommand.versions || (uint)_command >= 128) {
                cell_buffer.Write((ushort)(_payload.Length));
            }
            cell_buffer.Write(_payload);
            return cell_bytes;
        }

        internal void MarkAsValid()
        {
            _is_valid = true;
        }

        internal void ResizePayload(int newLength)
        {
            Helpers.Resize(ref _payload, newLength);
        }

        public const int size = 512;
        public const int header_size = 3;
        public const int variable_header_size = 5;
        public const int payload_size = size - header_size;
        protected uint _circuit_id = 0;
        protected CellCommand _command = (CellCommand)0;
        protected byte[] _payload;
        protected bool _is_valid = true;
    }
}
