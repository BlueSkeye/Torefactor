using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using TorNet.Cryptography;
using TorNet.IO;
using TorNet.Tor.Cryptography;

namespace TorNet.Tor
{
    internal class CircuitNode
    {
        public static byte[] DeriveKeys(byte[] secret)
        {
            List<byte> key_material = new List<byte>(100);
            List<byte>hashdata = new List<byte>(secret);
            hashdata.Add(0);

            for (byte index = 0; index< 5; index++) {
                hashdata[secret.Length] = index;
                key_material.AddRange(SHA1.Hash(hashdata.ToArray()));
            }
            return key_material.ToArray();
        }

        public CircuitNode(Circuit circuit, OnionRouter or,
            CircuitNode.Type node_type = CircuitNode.Type.normal)
        {
            _circuit = circuit;
            _type = node_type;
            _onion_router = or;
            _dh = new KeyAgrement((CircuitNode.Type.introduction_point == node_type)
                ? 128
                : Constants.DH_SEC_LEN);
        }

        public Circuit Circuit
        {
            get { return _circuit; }
        }

        public OnionRouter OnionRouter
        {
            get { return _onion_router; }
        }

        internal KeyAgrement KeyAgreement
        {
            get { return _dh; }
        }

        internal byte[] CreateOnionSkin()
        {
            return HybridEncryptor.Encrypt(_dh.PublicKey.ToBytes(),
                _onion_router.OnionKey);
        }

        // derivative key data, for verification of derivation
        internal void SetSharedSecret(BigInteger peer_public, byte[]kh)
        {
            // assert(kh.get_size() == 20)
            BigInteger shared_secret = _dh.GetSharedSecret(peer_public);
            byte[] key_material = DeriveKeys(shared_secret.ToBytes());

            if (Helpers.AreEquals(key_material, kh, kh.Length)) {
                _crypto_state = new CryptoState(key_material);
            }
        }

        internal bool HasValidCryptoState
        {
            get { return (null != _crypto_state); }
        }

        internal void EncryptForwardCell(RelayCell cell)
        {
            _crypto_state.encrypt_forward_cell(cell);
        }

        internal bool DecryptBackwardCell(Cell cell)
        {
            return _crypto_state.decrypt_backward_cell(cell);
        }

        internal void DecrementPackageWindow()
        {
            // called when a relay data cell has been sent (on this circuit node).
            lock(_window_mutex) {
                _package_window--;
                Logger.Debug("circuit_node::decrement_package_window() [ _package_window = {0} ]",
                    _package_window);
            }
        }

        internal void IncrementPackageWindow()
        {
            // called when a RELAY_SENDME with stream_id == 0 has been received.
            lock(_window_mutex) {
                _package_window += window_increment;
                Logger.Debug("circuit_node::increment_package_window() [ _package_window = {0} ]", 
                    _package_window);
            }
        }

        internal void DecrementDeliverWindow()
        {
            // called when a relay data cell has been received (on this circuit node).
            lock(_window_mutex) {
                _deliver_window--;
                Logger.Debug("circuit_node::decrement_deliver_window() [ _deliver_window = {0} ]",
                    _deliver_window);
            }
        }

        internal bool ConsiderSendingSendme()
        {
            lock(_window_mutex) {
                if (_deliver_window > (window_start - window_increment)) {
                    Logger.Debug("circuit_node::consider_sending_sendme(): false");
                    return false;
                }
                _deliver_window += window_increment;
                Logger.Debug("circuit_node::consider_sending_sendme(): true");
                return true;
            }
        }

        private const int window_start = 1000;
        private const int window_increment = 100;

        private Circuit _circuit;
        private CircuitNode.Type _type;

        private OnionRouter _onion_router;
        private CryptoState _crypto_state;
        private KeyAgrement _dh;

        private int _package_window = window_start;
        private int _deliver_window = window_start;
        private object _window_mutex= new object();

        private class CryptoState
        {
            internal CryptoState(byte[] key_material)
            {
                using (MemoryStream key_material_stream = new MemoryStream(key_material)) {
                    StreamWrapper key_material_buffer = new StreamWrapper(key_material_stream);
                    // skip checksum digest.
                    byte[] checksum_digest = new byte[20];
                    key_material_buffer.Read(checksum_digest);
                    byte[] df = new byte[20];
                    key_material_buffer.Read(df);
                    _forward_digest = CryptoProvider.Instance.CreateSha1();
                    _forward_digest.Update(df);
                    byte[] db = new byte[20];
                    key_material_buffer.Read(db);
                    _backward_digest = CryptoProvider.Instance.CreateSha1();
                    _backward_digest.Update(db);

                    byte[] kf = new byte[16];
                    key_material_buffer.Read(kf);
                    _forward_cipher = CryptoProvider.Instance.CreateAes();
                    _forward_cipher.init(AES.Mode.Ctr, AES.KeySize.Aes128, kf);
                    byte[] kb = new byte[16];
                    key_material_buffer.Read(kb);
                    _backward_cipher = CryptoProvider.Instance.CreateAes();
                    _backward_cipher.init(AES.Mode.Ctr, AES.KeySize.Aes128, kb);
                }
            }

            // ~CryptoState()

            internal void encrypt_forward_cell(RelayCell cell)
            {
                byte[] relay_payload_bytes = new byte[Cell.payload_size];

                if (Helpers.IsNullOrEmpty(cell.Payload)) {
                    MemoryStream relay_payload_stream = new MemoryStream(relay_payload_bytes);
                    StreamWrapper relay_payload_buffer = new StreamWrapper(relay_payload_stream, Endianness.big_endian);

                    relay_payload_buffer.Write((byte)cell.RelayCommand);
                    relay_payload_buffer.Write((ushort)(0)); // 'recognized'
                    relay_payload_buffer.Write(cell.StreamId);
                    relay_payload_buffer.Write((uint)(0)); // digest placeholder
                    relay_payload_buffer.Write((ushort)(cell.RelayPayload.Length));
                    relay_payload_buffer.Write(cell.RelayPayload);

                    // update digest field in the payload
                    _forward_digest.Update(relay_payload_bytes);
                    byte[] digest = _forward_digest.Duplicate().GetHash();
                    Buffer.BlockCopy(digest, 0, relay_payload_bytes, 5, 4);
                }
                else {
                    Buffer.BlockCopy(cell.Payload, 0, relay_payload_bytes, 0, cell.Payload.Length);
                }

                // encrypt the payload
                byte[] encrypted_payload = _forward_cipher.Update(relay_payload_bytes, false);
                Helpers.Resize(ref encrypted_payload, Cell.payload_size);

                // set the payload
                cell.Payload = encrypted_payload;
            }

            internal bool decrypt_backward_cell(Cell cell)
            {
                byte[] decrypted_payload = _backward_cipher.Update(cell.Payload, false);
                Helpers.Resize(ref decrypted_payload, Cell.payload_size);
                cell.Payload = decrypted_payload;

                // check if this is a cell for us.
                if (cell.Payload[1] == 0x00 && cell.Payload[2] == 0x00) {
                    // remove the digest from the payload
                    byte[] payload_without_digest = (byte[])cell.Payload.Clone();
                    byte[] nullDigest = new byte[4];
                    Buffer.BlockCopy(nullDigest, 0, payload_without_digest, 5, nullDigest.Length);
                    byte[] payload_digest = new byte[4];
                    Buffer.BlockCopy(cell.Payload, 5, payload_digest, 0, payload_digest.Length);
                    SHA1 backward_digest_clone = _backward_digest.Duplicate();
                    backward_digest_clone.Update(payload_without_digest);
                    byte[] digest = backward_digest_clone.GetHash();

                    if (Helpers.AreEquals(payload_digest, digest, 4)) {
                        _backward_digest.Update(payload_without_digest);
                        return true;
                    }
                }
                return false;
            }

            private AES _forward_cipher;
            private AES _backward_cipher;
            private SHA1 _forward_digest;
            private SHA1 _backward_digest;
        }

        internal enum Type
        {
            normal,
            introduction_point,
        }
    }
}
