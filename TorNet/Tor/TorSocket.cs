using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using TorNet.IO;

namespace TorNet.Tor
{
    internal class TorSocket
    {
        internal TorSocket(OnionRouter onion_router = null)
        {
            _onion_router = onion_router;
            _recv_cell_loop_thread = new Thread(ReceiveCellsLoop);
            if (null != onion_router) { Connect(onion_router); }
        }

        ~TorSocket()
        {
            Close();
        }

        internal void Connect(OnionRouter or)
        {
            _onion_router = or;
            _socket.Connect(_onion_router.IPAddress.ToString(), _onion_router.ORPort);
            State = SocketState.handshake_in_progress;
            // handshake.
            SendVersion();
            ReceiveVersions();
            ReceiveCertificates();
            ReceiveNetworkInfo();
            SendNetInfo();
            // start the receive loop.
            _recv_cell_loop_thread.Start();
        }

        internal void Close()
        {
            State = SocketState.closing;
            while (!_circuit_map.IsEmpty()) {
                Circuit victim = _circuit_map.LastValue();
                victim.SendDestroyCell();
                // this call will:
                //   close all the streams in the circuit
                //   remove the circuit from our circuit map.
                victim.Destroy();
            }
            Globals.Assert(_circuit_map.IsEmpty());
            _socket.Close();
            _recv_cell_loop_thread.Join();
            State = SocketState.closed;
        }

        internal Circuit CreateCircuit()
        {
            Circuit new_circuit = new Circuit(this);
            _circuit_map.Add(new_circuit.CircuitId, new_circuit);
            new_circuit.Create(_onion_router);
            return new_circuit;
        }

        internal void RemoveCircuit(Circuit circuit)
        {
            Logger.Debug("tor_socket::remove_circuit() [circuit: {0}]", circuit.CircuitId & 0x7FFFFFFF);
            _circuit_map.Remove(circuit.CircuitId);
        }

        internal void SendCell(Cell cell)
        {
            byte[] cell_content = cell.GetBytes((ushort)_protocol_version);
            _socket.Write(cell_content, cell_content.Length);
        }

        internal Cell ReceiveCell()
        {
            Cell cell = new Cell();

            do {
                StreamWrapper socket_buffer = new StreamWrapper(_socket, Endianness.big_endian);
                // get circuit id based on the current protocol version.
                uint circuit_id;
                byte[] buffer = new byte[sizeof(uint)];
                if (_protocol_version < 4) {
                    if (socket_buffer.Read(buffer, sizeof(ushort)) != sizeof(ushort)) {
                        break;
                    }
                    circuit_id = buffer.ToUInt16();
                }
                else {
                    if (socket_buffer.Read(buffer) != sizeof(uint)) {
                        break;
                    }
                    circuit_id = buffer.ToUInt32();
                }
                // get the cell command.
                if (socket_buffer.Read(buffer, sizeof(CellCommand)) != sizeof(CellCommand)) {
                    break;
                }
                CellCommand command = (CellCommand)(buffer[0]);
                // get payload size for variable-length cell types.
                ushort payload_size = 509;
                if (CellCommand.versions == command || (uint)command >= 128) {
                    if (socket_buffer.Read(buffer, sizeof(ushort)) != sizeof(ushort)) {
                        break;
                    }
                    payload_size = buffer.ToUInt16();
                }
                // get the content of the payload.
                byte[] payload = new byte[payload_size];
                if (socket_buffer.Read(payload, payload_size) != payload_size) {
                    break;
                }
                // build the cell
                cell.CircuitId = circuit_id;
                cell.Command = command;
                cell.Payload = payload;
                cell.MarkAsValid();
            } while (false);
            return cell;
        }

        internal ushort ProcotolVersion
        {
            get { return (ushort)_protocol_version; }
        }

        internal OnionRouter OnionRouter
        {
            get { return _onion_router; }
        }

        internal Circuit GetCircuitById(uint circuit_id)
        {
            Circuit circuit;
            return (_circuit_map.TryGetValue(circuit_id, out circuit)) ? circuit : null;
        }

        internal bool IsConnected
        {
            get { return _socket.IsConnected; }
        }

        internal SocketState State
        {
            get { lock (_stateChangeEvent) { return _state; } }
            set {
                lock (_stateChangeEvent) { 
                    _state = value;
                    _stateChangeEvent.Set();
                }
            }
        }

        internal void WaitForState(SocketState desiredState)
        {
            Monitor.Enter(_stateChangeEvent);
            while (_state != desiredState) {
                Monitor.Exit(_stateChangeEvent);
                _stateChangeEvent.WaitOne(Timeout.Infinite);
                Monitor.Enter(_stateChangeEvent);
            }
            return;
        }

        internal void SendVersion()
        {
            Logger.Debug("tor_socket::send_versions()");
            // static constexpr protocol_version_type supported_versions[] = { 4 };
            SendCell(new Cell(0, CellCommand.versions, new byte[] { 0, 4 }));
        }

        internal void ReceiveVersions()
        {
            Logger.Debug("tor_socket::recv_versions()");
            Cell versions_cell = ReceiveCell();

            MemoryStream versions_stream = new MemoryStream(versions_cell.Payload);
            StreamWrapper versions_buffer = new StreamWrapper(versions_stream, Endianness.big_endian);

            for (int i = 0; i < versions_cell.Payload.Length; i += 2) {
                ushort offered_version = versions_buffer.ReadUInt16();
                if (offered_version == protocol_version_preferred) {
                    _protocol_version = offered_version;
                }
            }
        }

        internal void SendNetInfo()
        {
            Logger.Debug("tor_socket::send_net_info()");

            uint remote = _socket.UnderlyingSocket.IPAddress.GetAddressBytes().ToUInt32();
            uint local = 0; // FIXME: local IP address.
            uint epoch = (uint)DateTime.Now.SecondsSinceEpoch();

            byte[] net_info_bytes = new byte[4 + 2 + 4 + 3 + 4];
            MemoryStream net_info_stream = new MemoryStream(net_info_bytes);
            StreamWrapper net_info_buffer = new StreamWrapper(net_info_stream, Endianness.big_endian);

            //
            // If version 2 or higher is negotiated, each party sends the other a
            // NETINFO cell.  The cell's payload is:
            //
            //  Timestamp              [4 bytes]
            //  Other OR's address     [variable]
            //  Number of addresses    [1 byte]
            //  This OR's addresses    [variable]
            //
            // Address is:
            //   Type   (1 octet)
            //   Length (1 octet)
            //   Value  (variable-width)
            //
            //  "Type" is one of:
            //    0x00 -- Hostname
            //    0x04 -- IPv4 address
            //    0x06 -- IPv6 address
            //    0xF0 -- Error, transient
            //    0xF1 -- Error, nontransient
            //

            net_info_buffer.Write(epoch);
            net_info_buffer.Write((byte)0x04); // type
            net_info_buffer.Write((byte)0x04); // length
            net_info_buffer.Write(remote.ToArray().SwapEndianness());
            net_info_buffer.Write((byte)0x01); // number of addresses
            net_info_buffer.Write((byte)0x04); // type
            net_info_buffer.Write((byte)0x04); // length
            net_info_buffer.Write(local.ToArray().SwapEndianness());
            SendCell(new Cell(0, CellCommand.netinfo, net_info_bytes));
        }

        internal void ReceiveNetworkInfo()
        {
            ReceiveCell(); // netinfo
            Logger.Debug("tor_socket::recv_net_info()");
        }

        internal void SendCertificates()
        {
        }

        internal void ReceiveCertificates()
        {
            ReceiveCell(); // certs
            ReceiveCell(); // auth_challenge
            Logger.Debug("tor_socket::recv_certificates()");
        }

        internal void ReceiveCellsLoop()
        {
            State = SocketState.ready;
            while (true) {
                Cell cell = ReceiveCell();
                if (SocketState.closing == State) {
                    // probably end of the stream.
                    break;
                }
                if (!cell.IsValid) {
                    // TODO : Bug in original source code. Connection id is missing.
                    Logger.Warning("tor_socket::recv_cell_loop() !! received invalid cell, stream has ended the connection {0}",
                        "UNKNOWN");
                    break;
                }
                Circuit circuit = GetCircuitById(cell.CircuitId);
                if (null != circuit) {
                    circuit.HandleCell(cell);
                }
                else {
                    Logger.Warning("tor_socket::recv_cell_loop() !! received cell for non-existent circuit-id: {0}",
                      cell.CircuitId & 0x7fffffff);
                }
            }
        }

        private SslSocket _socket;
        private OnionRouter _onion_router;
        private uint _protocol_version = 3;

        private Thread _recv_cell_loop_thread;
        private SortedList<uint, Circuit> _circuit_map = new SortedList<uint, Circuit>();
        private SocketState _state = SocketState.connecting;
        private AutoResetEvent _stateChangeEvent = new AutoResetEvent(false);

        public const ushort protocol_version_preferred = 4;

        internal enum SocketState
        {
            connecting,
            handshake_in_progress,
            ready,
            closing,
            closed,
        }
    }
}
