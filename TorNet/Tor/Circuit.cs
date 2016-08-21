using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using TorNet.Cryptography;
using TorNet.Tor.Cryptography;
using TorNet.IO;

namespace TorNet.Tor
{
    internal class Circuit : IDisposable
    {
        public Circuit(TorSocket tor_socket)
        {
            _tor_socket = tor_socket;
            _circuit_id = NextCircuitId;
            _circuit_id |= 0x80000000;
        }

        ~Circuit()
        {
            SendDestroyCell();
            Destroy();
        }

        internal TorSocket TorSocket
        {
            get { return _tor_socket; }
        }

        public uint CircuitId
        {
            get { return _circuit_id; }
        }

        private CircuitNode FinalCircuitNode
        {
            get { return _node_list[_node_list.Count - 1]; }
        }

        private TorStream CreateStream(string host, int port)
        {
            // tor-spec.txt
            // 6.2.
            //
            // ADDRPORT [nul-terminated string]
            // FLAGS[4 bytes]
            //
            // ADDRPORT is made of ADDRESS | ':' | PORT | [00]
            byte[] relay_data_bytes = new byte[100];
            MemoryStream relay_data_stream = new MemoryStream(relay_data_bytes);
            StreamWrapper relay_data_buffer = new StreamWrapper(relay_data_stream, Endianness.big_endian);

            string ps = port.ToString();

            string hp = host + ":" + ps;
            relay_data_buffer.Write(hp);
            // null terminator.
            relay_data_buffer.Write((byte)0);
            // flags.
            relay_data_buffer.Write((uint)(0));
            // send RELAY_BEGIN cell.
            ushort stream_id = NextStreamId;
            TorStream stream = new TorStream(stream_id, this);
            _stream_map.Add(stream_id, stream);
            Logger.Debug("circuit::create_stream() [url: %s, stream: %u, status: creating]", hp, stream_id);
            this.State = CircuitState.connecting;
            SendRelayCell(stream_id, CellCommand.relay_begin, relay_data_bytes);
            WaitForState(CircuitState.ready);
            Logger.Debug("circuit::create_stream() [url: %s, stream: %u, status: created]", hp, stream_id);
            return stream;
        }

        private TorStream create_onion_stream(string onion, int port)
        {
            HiddenService hidden_service_connector = new HiddenService(this, onion);
            hidden_service_connector.Connect();
            return CreateStream(onion, port);
        }

        internal TorStream CreateDirStream()
        {
            ushort stream_id = NextStreamId;
            TorStream stream = new TorStream(stream_id, this);
            _stream_map.Add(stream_id, stream);

            Logger.Debug("circuit::create_dir_stream() [stream: %u, state: connecting]", stream_id);
            this.State = CircuitState.connecting;
            SendRelayCell(stream_id, CellCommand.relay_begin_dir);
            WaitForState(CircuitState.ready);
            Logger.Debug("circuit::create_dir_stream() [stream: %u, state: connected]", stream_id);
            return stream;
        }

        internal void Create(OnionRouter firstRouter)
        {
            Logger.Debug("circuit::create() [or: {0}, state: creating]", firstRouter.Name);
            this.State = CircuitState.creating;
            _extend_node = CreateCircuitNode(firstRouter);
            SendCell(new Cell(_circuit_id, CellCommand.create, _extend_node.CreateOnionSkin()));
            WaitForState(CircuitState.ready);
            Logger.Debug("circuit::create() [or: {0}, state: created]", firstRouter.Name);
        }

        internal void Destroy()
        {
            if (Circuit.CircuitState.destroyed == this.State) { return; }
            Logger.Debug("circuit::destroy()");
            CloseStreams();
            _tor_socket.RemoveCircuit(this);
        }

        public void Dispose()
        {
            Destroy();
        }

        internal void Extend(OnionRouter next_onion_router)
        {
            Logger.Debug("circuit::extend() [or: {0}, state: extending]", next_onion_router.Name);
            this.State = CircuitState.extending;
            _extend_node = CreateCircuitNode(next_onion_router);
            byte[] onion_skin = _extend_node.CreateOnionSkin();

            byte[] relay_payload_bytes = new byte[] {
                (byte)(
                4 +                         // ip address
                2 +                         // port
                onion_skin.Length +     // hybrid encrypted data length
                Constants.HASH_LEN) };                  // identity fingerprint

            MemoryStream relay_payload_stream = new MemoryStream(relay_payload_bytes);
            StreamWrapper relay_payload_buffer = new StreamWrapper(relay_payload_stream, Endianness.big_endian);

            relay_payload_buffer.Write(next_onion_router.IPAddress.GetAddressBytes().SwapEndianness());
            relay_payload_buffer.Write(next_onion_router.ORPort);
            relay_payload_buffer.Write(onion_skin);
            relay_payload_buffer.Write(Base16.Decode(next_onion_router.IdentityFingerprint));

            SendRelayCell(0, CellCommand.relay_extend, relay_payload_bytes,
                // clients MUST only send
                // EXTEND cells inside RELAY_EARLY cells
                CellCommand.relay_early, _extend_node);
            WaitForState(Circuit.CircuitState.ready);
            Logger.Debug("circuit::extend() [or: {0}, state: extended]", next_onion_router.Name);
        }

        internal TorStream GetStreamById(ushort stream_id)
        {
            TorStream stream;
            return _stream_map.TryGetValue(stream_id, out stream) ? stream : null;
        }

        private void CloseStreams()
        {
            // destroy each stream in this circuit.
            while (!_stream_map.IsEmpty()) {
                // this call removes the stream from our stream map.
                SendRelayEndCell(_stream_map.LastValue());
            }
            this.State = Circuit.CircuitState.destroyed;
        }

        private CircuitNode CreateCircuitNode(OnionRouter or,
            CircuitNode.Type type = CircuitNode.Type.normal)
        {
            return new CircuitNode(this, or, type);
        }

        internal void RendezvousEstablish(byte[] rendezvous_cookie)
        {
            Globals.Assert(20 == rendezvous_cookie.Length);
            Logger.Debug("circuit::rendezvous_establish() [circuit: {0}, state: establishing]", _circuit_id);
            this.State = Circuit.CircuitState.rendezvous_establishing;
            SendRelayCell(0, CellCommand.relay_command_establish_rendezvous, rendezvous_cookie);
            WaitForState(Circuit.CircuitState.rendezvous_established);
            Logger.Debug("circuit::rendezvous_establish() [circuit: {0}, state: established]", _circuit_id);
        }

        internal void RendezvousIntroduce(Circuit rendezvous_circuit,
            byte[] rendezvous_cookie)
        {
            Globals.Assert(rendezvous_cookie.Length == 20);
            OnionRouter introduction_point = FinalCircuitNode.OnionRouter;
            OnionRouter introducee = rendezvous_circuit.FinalCircuitNode.OnionRouter;
            Logger.Debug("circuit::rendezvous_introduce() [or: {0}, state: introducing]",
                introduction_point.Name);
            this.State = Circuit.CircuitState.rendezvous_introducing;
            Logger.Debug("circuit::rendezvous_introduce() [or: {0}, state: completing]",
                introduction_point.Name);
            rendezvous_circuit.State = CircuitState.rendezvous_completing;
            // payload of the RELAY_COMMAND_INTRODUCE1
            // command:
            //
            // PK_ID  Identifier for Bob's PK      [20 octets]
            // VER    Version byte: set to 2.        [1 octet]
            // IP     Rendezvous point's address    [4 octets]
            // PORT   Rendezvous point's OR port    [2 octets]
            // ID     Rendezvous point identity ID [20 octets]
            // KLEN   Length of onion key           [2 octets]
            // KEY    Rendezvous point onion key [KLEN octets]
            // RC     Rendezvous cookie            [20 octets]
            // g^x    Diffie-Hellman data, part 1 [128 octets]
            //

            // compute PK_ID, aka hash of the service key.
            byte[] service_key_hash = SHA1.Hash(introduction_point.ServiceKey);

            // create rest of the payload in separate buffer;
            // it will be encrypted.
            byte[] handshake_bytes = new byte[] { (byte)(
                1 +                                       // version
                4 +                                       // ip address
                2 +                                       // port
                Constants.HASH_LEN +                      // identity_fingerprint
                2 +                                       // onion key size
                introducee.OnionKey.Length +              // onion key
                20 +                                      // rendezvous cookie
                128) };                                    // DH
            MemoryStream handshake_stream = new MemoryStream(handshake_bytes);
            StreamWrapper handshake_buffer = new StreamWrapper(handshake_stream, Endianness.big_endian);
            rendezvous_circuit._extend_node = CreateCircuitNode(introduction_point,
                CircuitNode.Type.introduction_point);
            handshake_buffer.Write((byte)2);
            handshake_buffer.Write(introducee.IPAddress.GetAddressBytes().SwapEndianness());
            handshake_buffer.Write(introducee.ORPort);
            handshake_buffer.Write(Base16.Decode(introducee.IdentityFingerprint));
            handshake_buffer.Write((ushort)(introducee.OnionKey.Length));
            handshake_buffer.Write(introducee.OnionKey);
            handshake_buffer.Write(rendezvous_cookie);
            handshake_buffer.Write(rendezvous_circuit._extend_node.KeyAgreement.PublicKey.ToBytes());

            byte[] handshake_encrypted = HybridEncryptor.Encrypt(handshake_bytes,
                introduction_point.ServiceKey);
            // compose the final payload.
            List<byte> relay_payload_bytes = new List<byte>();
            relay_payload_bytes.AddRange(service_key_hash);
            relay_payload_bytes.AddRange(handshake_encrypted);
            // send the cell.
            SendRelayCell(0, CellCommand.relay_command_introduce1, relay_payload_bytes.ToArray());
            WaitForState(Circuit.CircuitState.rendezvous_introduced);
            Logger.Debug("circuit::rendezvous_introduce() [or: {0}, state: introduced]",
                introduction_point.Name);
            rendezvous_circuit.WaitForState(Circuit.CircuitState.rendezvous_completed);
            Logger.Debug("circuit::rendezvous_introduce() [or: {0}, state: completed]",
                introduction_point.Name);
        }

        private Cell Encrypt(RelayCell cell)
        {
            for (int i = (int)_node_list.Count - 1; i >= 0; i--) {
                _node_list[i].EncryptForwardCell(cell);
            }
            return cell;
        }

        private RelayCell Decrypt(Cell cell)
        {
            foreach (CircuitNode node in _node_list) {
                if (node.DecryptBackwardCell(cell)) {
                    return new RelayCell(node, cell);
                }
            }
            return new RelayCell();
        }

        private void SendCell(Cell cell)
        {
            _tor_socket.SendCell(cell);
        }

        internal void SendDestroyCell()
        {
            SendCell(new Cell(_circuit_id, CellCommand.destroy, null));
        }

        private void SendRelayCell(ushort stream_id, CellCommand relay_command,
            byte[] payload = null, CellCommand cell_command = CellCommand.relay,
            CircuitNode node = null)
        {
            node = node ?? FinalCircuitNode;

            if ((null == GetStreamById(stream_id)) && (0 != stream_id)) {
                Logger.Warning("circuit::send_relay_cell() attempt to send cell to non-existent stream-id: {0}",
                    stream_id);
                return;
            }

            Logger.Debug("tor_socket::send_cell() [circuit: %i%s, stream: %u, command: %i, relay_command: %i]",
                _circuit_id & 0x7FFFFFFF,
                ((0 != (_circuit_id & 0x80000000)) ? " (MSB set)" : ""),
                stream_id, cell_command, relay_command);
            SendCell(
                Encrypt(
                    new RelayCell(_circuit_id, cell_command, node, relay_command,
                        stream_id, payload)));
        }

        private const int max_data_size = 509 - 1 - 2 - 2 - 4 - 2;

        internal void SendRelayDataCell(TorStream stream, byte[] buffer)
        {
            for (int i = 0; i < Helpers.RoundUp(buffer.Length, max_data_size); i += max_data_size) {
                int data_size = Math.Min(buffer.Length - i, max_data_size);
                FinalCircuitNode.DecrementPackageWindow();
                SendRelayCell(stream.StreamId, CellCommand.relay_data,
                    buffer.Slice(i, i + data_size));
            }
        }

        internal void SendRelayEndCell(TorStream stream)
        {
            SendRelayCell(stream.StreamId, CellCommand.relay_end, new byte[] { 6 }); // reason
            stream.State = TorStream.StreamState.destroyed;
            _stream_map.Remove(stream.StreamId);
        }

        private void SendRelaySendmeCell(TorStream stream)
        {
            // if stream == nullptr, we're sending RELAY_SENDME
            // with stream_id = 0, which means circuit RELAY_SENDME
            SendRelayCell((ushort)((null == stream) ? 0 : stream.StreamId), CellCommand.relay_sendme, null);
        }

        internal void HandleCell(Cell cell)
        {
            if (CellCommand.relay != cell.Command) {
                Logger.Debug("tor_socket::recv_cell() [circuit: {0}{1}, command: {2}]",
                    cell.CircuitId & 0x7FFFFFFF, 
                    ((0 != (cell.CircuitId & 0x80000000)) ? " (MSB set)" : ""),
                    cell.Command);
            }

            switch (cell.Command) {
                case CellCommand.created:
                    HandleCreatedCell(cell);
                    break;
                case CellCommand.destroy:
                    HandleDestroyedCell(cell);
                    break;
                case CellCommand.relay:
                    RelayCell decrypted_relay_cell = Decrypt(cell);
                    if (!decrypted_relay_cell.IsRelayCellValid) {
                        Logger.Warning("circuit::handle_cell() cannot decrypt relay cell, destroying circuit");
                        Destroy();
                        break;
                    }
                    Logger.Debug("tor_socket::recv_cell() [circuit: %i%s, stream: %u, command: %u, relay_command: %u, payload_size: %u]",
                        decrypted_relay_cell.CircuitId & 0x7FFFFFFF,
                        ((0 != (decrypted_relay_cell.CircuitId & 0x80000000)) ? " (MSB set)" : ""),
                        decrypted_relay_cell.StreamId,
                        decrypted_relay_cell.Command,
                        decrypted_relay_cell.RelayCommand,
                        decrypted_relay_cell.RelayPayload.Length);

                    switch (decrypted_relay_cell.RelayCommand) {
                        case CellCommand.relay_truncated:
                            HandleRelayTruncatedCell(decrypted_relay_cell);
                            break;
                        case CellCommand.relay_end:
                            HandleRelayEndCell(decrypted_relay_cell);
                            break;
                        case CellCommand.relay_connected:
                            HandleRelayConnectedCell(decrypted_relay_cell);
                            break;
                        case CellCommand.relay_extended:
                            HandleRelayExtendedCell(decrypted_relay_cell);
                            break;
                        case CellCommand.relay_data:
                            HandleRelayDataCell(decrypted_relay_cell);
                            break;
                        case CellCommand.relay_sendme:
                            HandleRelaySendmeCell(decrypted_relay_cell);
                            break;
                        case CellCommand.relay_command_rendezvous2:
                            HandleRelayExtendedCell(decrypted_relay_cell);
                            this.State = Circuit.CircuitState.rendezvous_completed;
                            break;
                        case CellCommand.relay_command_rendezvous_established:
                            this.State = Circuit.CircuitState.rendezvous_established;
                            break;
                        case CellCommand.relay_command_introduce_ack:
                            this.State = Circuit.CircuitState.rendezvous_introduced;
                            break;
                        default:
                            Logger.Warning("tor_socket::recv_cell() !! unhandled relay cell [ relay_command: %u ]",
                                decrypted_relay_cell.RelayCommand);
                            break;
                    }
                    break;
                default:
                    break;
            }
        }

        private void HandleCreatedCell(Cell cell)
        {
            // finish the handshake.
            _extend_node.SetSharedSecret(BigInteger.FromBytes(cell.Payload.Slice(0, Constants.DH_LEN)),
                cell.Payload.Slice(Constants.DH_LEN, Constants.DH_LEN + Constants.HASH_LEN));
            if (_extend_node.HasValidCryptoState) {
                _node_list.Add(_extend_node);
            }
            else {
                Logger.Warning("circuit::handle_created_cell() extend node [ {0} ] has invalid crypto state",
                    _extend_node.OnionRouter.Name);
            }
            // we're ready here.
            _extend_node = null;
            this.State = Circuit.CircuitState.ready;
        }

        private void HandleDestroyedCell(Cell cell)
        {
            Destroy();
        }

        private void HandleRelayExtendedCell(RelayCell cell)
        {
            // finish the handshake.
            _extend_node.SetSharedSecret(BigInteger.FromBytes(cell.RelayPayload.Slice(0, Constants.DH_LEN)),
                cell.RelayPayload.Slice(Constants.DH_LEN, Constants.DH_LEN + Constants.HASH_LEN));

            if (_extend_node.HasValidCryptoState) {
                _node_list.Add(_extend_node);
            }
            else {
                Logger.Warning(
                    "circuit::handle_relay_extended_cell() extend node [ {0} ] has invalid crypto state",
                    _extend_node.OnionRouter.Name);
            }
            // we're ready here.
            _extend_node = null;
            this.State = Circuit.CircuitState.ready;
        }

        private void HandleRelayDataCell(RelayCell cell)
        {
            // decrement deliver window on circuit node.
            cell.CircuitNode.DecrementDeliverWindow();
            if (cell.CircuitNode.ConsiderSendingSendme()) {
                SendRelaySendmeCell(null);
            }
            TorStream stream = GetStreamById(cell.StreamId);
            if (null != stream) {
                stream.AppendToReceiveBuffer(cell.RelayPayload);
                // decrement window on stream.
                stream.DecrementDeliverWindows();
                if (stream.ConsiderSendingSendme()) {
                    SendRelaySendmeCell(stream);
                }
            }
        }

        private void HandleRelaySendmeCell(RelayCell cell)
        {
            if (cell.StreamId == 0) {
                cell.CircuitNode.IncrementPackageWindow();
                return;
            }
            TorStream stream = GetStreamById(cell.StreamId);
            if (null != stream) {
                stream.IncrementPackageWindows();
            }
        }

        private void HandleRelayConnectedCell(RelayCell cell)
        {
            TorStream stream = GetStreamById(cell.StreamId);
            if (null != stream) {
                stream.State = TorStream.StreamState.ready;
            }
            this.State = Circuit.CircuitState.ready;
        }

        private void HandleRelayTruncatedCell(RelayCell cell)
        {
            // tor-spec.txt
            // 5.4.
            //
            // To tear down part of a circuit, the OP may send a RELAY_TRUNCATE cell
            // signaling a given OR (Stream ID zero).  That OR sends a DESTROY
            // cell to the next node in the circuit, and replies to the OP with a
            // RELAY_TRUNCATED cell.
            //
            // [Note: If an OR receives a TRUNCATE cell and it has any RELAY cells
            // still queued on the circuit for the next node it will drop them
            // without sending them.  This is not considered conformant behavior,
            // but it probably won't get fixed until a later version of Tor.  Thus,
            // clients SHOULD NOT send a TRUNCATE cell to a node running any current
            // version of Tor if a) they have sent relay cells through that node,
            // and b) they aren't sure whether those cells have been sent on yet.]
            //
            // When an unrecoverable error occurs along one connection in a
            // circuit, the nodes on either side of the connection should, if they
            // are able, act as follows:  the node closer to the OP should send a
            // RELAY_TRUNCATED cell towards the OP; the node farther from the OP
            // should send a DESTROY cell down the circuit.
            //
            Logger.Warning("circuit::handle_relay_truncated_cell() destroying circuit");
            Destroy();
        }

        private void HandleRelayEndCell(RelayCell cell)
        {
            TorStream stream = GetStreamById(cell.StreamId);
            if (null != stream) {
                Logger.Debug("circuit::handle_relay_end_cell() [stream: {0}, reason: {1}]",
                    cell.StreamId, cell.RelayPayload[0]);
                stream.State = TorStream.StreamState.destroyed;
                _stream_map.Remove(cell.StreamId);
            }
        }

        private uint NextCircuitId
        {
            get { return next_circuit_id++; }
        }

        private ushort NextStreamId
        {
            get { return next_stream_id++; }
        }

        internal CircuitState State
        {
            get { lock (_stateChangeEvent) { return _state; } }
            set
            {
                lock (_stateChangeEvent) {
                    _state = value;
                    _stateChangeEvent.Set();
                }
            }
        }

        private void WaitForState(CircuitState desired_state)
        {
            Monitor.Enter(_stateChangeEvent);
            while (_state != desired_state) {
                Monitor.Exit(_stateChangeEvent);
                _stateChangeEvent.WaitOne(Timeout.Infinite);
                Monitor.Enter(_stateChangeEvent);
            }
            return;
        }

        //friend class tor_stream;
        //friend class tor_socket;
        //friend class hidden_service;

        private static volatile uint next_circuit_id = 1;
        private uint _circuit_id;
        private CircuitNode _extend_node = null;
        private static volatile ushort next_stream_id = 1;
        private List<CircuitNode> _node_list = new List<CircuitNode>();
        private CircuitState _state;
        private AutoResetEvent _stateChangeEvent = new AutoResetEvent(false);
        private TorSocket _tor_socket;
        private SortedList<ushort, TorStream> _stream_map = new SortedList<ushort, TorStream>();

        internal enum CircuitState
        {
            none,
            creating,
            extending,
            connecting,
            ready,
            destroyed,

            rendezvous_establishing,
            rendezvous_established,
            rendezvous_introducing,
            rendezvous_introduced,
            rendezvous_completing,
            rendezvous_completed,
        }
    }
}
