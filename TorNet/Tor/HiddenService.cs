using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using TorNet.Cryptography;
using TorNet.IO;
using TorNet.Tor.Parsers;

namespace TorNet.Tor
{
    internal class HiddenService
    {
        public HiddenService(Circuit rendezvous_circuit, string onion)
        {
            this._rendezvous_circuit = rendezvous_circuit;
            this._socket = rendezvous_circuit.TorSocket;
            this._owner = rendezvous_circuit.TorSocket.OnionRouter.Owner;
            this._onion = onion;
            this._permanent_id = Base32.decode(_onion);
            Logger.Info("hidden_service() [{0}.onion]", onion);
        }

        internal bool Connect()
        {
            FindResponsibleDirectories();
            if (!Helpers.IsNullOrEmpty(_responsible_directory_list)) {
                // create rendezvous cookie.
                CryptoProvider.Instance.CreateRandom().get_random_bytes(_rendezvous_cookie);
                // establish rendezvous.
                _rendezvous_circuit.RendezvousEstablish(_rendezvous_cookie);
                int responsible_directory_index = 0;
                while (-1 != (responsible_directory_index = FetchHiddenServiceDescriptor(responsible_directory_index))) {
                    // introduce rendezvous.
                    Introduce();
                    if (_rendezvous_circuit.State == Circuit.CircuitState.rendezvous_completed) {
                        return true;
                    }
                }
            }
            return false;
        }

        private byte[] GetSecretId(byte replica)
        {
            byte permanent_id_byte = _permanent_id[0];
            // rend-spec.txt
            // 1.3.
            //
            // "time-period" changes periodically as a function of time and
            // "permanent-id". The current value for "time-period" can be calculated
            // using the following formula:
            //
            //   time-period = (current-time + permanent-id-byte * 86400 / 256) / 86400
            uint time_period = (uint)(DateTime.Now.SecondsSinceEpoch() + (permanent_id_byte * 86400 / 256)) / 86400;
            byte[] secret_bytes = new byte[5];
            MemoryStream secret_stream = new MemoryStream(secret_bytes);
            StreamWrapper secret_buffer= new StreamWrapper(secret_stream, Endianness.big_endian);
            secret_buffer.Write(time_period);
            secret_buffer.Write(replica);
            return SHA1.Hash(secret_bytes);
        }

        private byte[] GetDescriptorId(byte replica)
        {
            byte[] secret_id = GetSecretId(replica);

            List<byte> descriptor_id_bytes = new List<byte>();
            descriptor_id_bytes.AddRange(_permanent_id);
            descriptor_id_bytes.AddRange(secret_id);
            return SHA1.Hash(descriptor_id_bytes.ToArray());
        }

        private void FindResponsibleDirectories()
        {
            // rend-spec.txt
            // 1.4.
            // At any time, there are 6 hidden service directories responsible for
            // keeping replicas of a descriptor; they consist of 2 sets of 3 hidden
            // service directories with consecutive onion IDs. Bob's OP learns about
            // the complete list of hidden service directories by filtering the
            // consensus status document received from the directory authorities. A
            // hidden service directory is deemed responsible for a descriptor ID if
            // it has the HSDir flag and its identity digest is one of the first three
            // identity digests of HSDir relays following the descriptor ID in a
            // circular list. A hidden service directory will only accept a descriptor
            // whose timestamp is no more than three days before or one day after the
            // current time according to the directory's clock.
            //
            _responsible_directory_list.Clear();
            List<OnionRouter> directory_list =
                _owner.get_onion_routers_by_criteria(
                    new Consensus.SearchCriteria() {
                        flags = OnionRouter.StatusFlags.HSDir | OnionRouter.StatusFlags.V2Dir
                    }
            );

            // search for the 2 sets of 3 hidden service directories.
            for (byte replica = 0; replica < 2; replica++)
            {
                byte[] descriptor_id = GetDescriptorId(replica);
                string descriptor_id_hex = Base16.Encode(descriptor_id);

                int index = Helpers.lower_bound(directory_list,
                  descriptor_id_hex, delegate(OnionRouter lhs, string rhs) {
                      return lhs.IdentityFingerprint.CompareTo(rhs) < 0;
                  });
                for (int i = 0; i < 3; i++) {
                    _responsible_directory_list.Add(
                        directory_list[(index + i) % directory_list.Count]);
                }
            }
        }

        private int FetchHiddenServiceDescriptor(int responsible_directory_index = 0)
        {
            for (int i = responsible_directory_index;
              i < _responsible_directory_list.Count;
              i++)
            {
                OnionRouter responsible_directory = _responsible_directory_list[i];
                // create new circuit and extend it with responsible directory.
                Circuit directory_circuit = _socket.CreateCircuit();
                directory_circuit.Extend(responsible_directory);
                byte replica = (byte)((i >= 3) ? 0 : 1);
                // create the directory stream on the directory circuit.
                TorStream directory_stream = directory_circuit.CreateDirStream();
                // request the hidden service descriptor.
                Logger.Info(
                  "hidden_service::fetch_hidden_service_descriptor() [path: {0}]",
                  ("/tor/rendezvous2/" + Base32.encode(GetDescriptorId(replica))));

                string request = "GET /tor/rendezvous2/" + Base32.encode(GetDescriptorId(replica)) + " HTTP/1.1\r\nHost: " + responsible_directory.IPAddress.ToString() + "\r\n\r\n";
                directory_stream.Write(ASCIIEncoding.ASCII.GetBytes(request), 0, request.Length);

                StreamReader stream_reader = new StreamReader(directory_stream);
                string hidden_service_descriptor = stream_reader.ReadToEnd();
                // parse hidden service descriptor.
                if (!hidden_service_descriptor.Contains("404 Not found")) {
                    HiddenServiceDescriptorParser parser = new HiddenServiceDescriptorParser();
                    parser.parse(_owner, hidden_service_descriptor);
                    _introduction_point_list = parser.introduction_point_list;
                    parser.introduction_point_list = null;
                    return i;
                }
            }
            return -1;
        }

        private void Introduce()
        {
            foreach (OnionRouter introduction_point in _introduction_point_list) {
                Circuit introduce_circuit = _socket.CreateCircuit();
                introduce_circuit.Extend(introduction_point);
                introduce_circuit.RendezvousIntroduce(_rendezvous_circuit, _rendezvous_cookie);
                if (Circuit.CircuitState.rendezvous_introduced == introduce_circuit.State) {
                    break;
                }
            }
        }

        private ConsensusOrVote _owner;
        private string _onion;
        private byte[] _permanent_id; // crypto::base32::decode(_onion)
        private Circuit _rendezvous_circuit;
        private TorSocket _socket;

        private List<OnionRouter> _responsible_directory_list;
        private List<OnionRouter> _introduction_point_list;
        private byte[] _rendezvous_cookie= new byte[20];
    }
}