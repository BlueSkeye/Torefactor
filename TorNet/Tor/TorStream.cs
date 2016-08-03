using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TorNet.Tor
{
    internal class TorStream : Stream
    {
        public TorStream(ushort stream_id, Circuit circuit)
        {
            _stream_id = stream_id;
            _circuit = circuit;
        }

        ~TorStream()
        {
            Close();
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // pull data.
            while(true) {
                lock(_buffer_mutex) {
                    if (0 != _buffer.Count) { break; }
                }
                if (StreamState.destroyed == this.State) { break; }
                Thread.Sleep(10);
            }
            // process data
            int result;
            lock(_buffer_mutex) {
                result = Math.Min(count, _buffer.Count);
                Buffer.BlockCopy(_buffer.ToArray(), 0, buffer, 0, result);
                _buffer = new List<byte>(_buffer.ToArray().Slice(result));
            }
            return result;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (StreamState.destroyed == this.State) {
                Logger.Warning("tor_stream::write() !! attempt to write to destroyed stream");
                return;
            }
            // flush immediatelly.
            byte[] data;
            if ((0 == offset) && (buffer.Length == count)) {
                data = buffer;
            }
            else {
                data = new byte[count];
                Buffer.BlockCopy(buffer, offset, data, 0, count);
            }
            _circuit.SendRelayDataCell(this, data);
            return;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return 0;
        }

        public override void Flush()
        {
            return;
        }

        public int Size
        {
            get { return 0; }
        }

        public override long Position
        {
            get { return 0; }
            set { throw new NotSupportedException(); }
        }

        public ushort StreamId
        {
            get { return _stream_id; }
        }

        public override void Close()
        {
            if (StreamState.destroyed == this.State) { return; }
            // send RELAY_END cell to the circuit.
            // the circuit will remove this stream from its stream map.
            _circuit.SendRelayEndCell(this);
        }

        internal void AppendToReceiveBuffer(ICollection<byte> appended)
        {
            lock(_buffer_mutex) { _buffer.AddRange(appended); }
        }

        public StreamState State
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

        private void WaitForState(TorStream.StreamState desired_state)
        {
            Monitor.Enter(_stateChangeEvent);
            while (_state != desired_state) {
                Monitor.Exit(_stateChangeEvent);
                _stateChangeEvent.WaitOne(Timeout.Infinite);
                Monitor.Enter(_stateChangeEvent);
            }
            return;
        }

        private void DecrementPackageWindow()
        {
            // called when a relay data cell has been sent (on this stream).
            lock (_window_mutex) {
                _package_window--;
                Logger.Debug("tor_stream::decrement_package_window() [ _package_window = {0} ]", _package_window);
            }
        }

        internal void IncrementPackageWindows()
        {
            // called when a RELAY_SENDME with current stream_id has been received.
            lock(_window_mutex) {
                _package_window += window_increment;
                Logger.Debug("tor_stream::increment_package_window() [ _package_window = {0} ]", _package_window);
            }
        }

        internal void DecrementDeliverWindows()
        {
            // called when a relay data cell has been received (on this stream).
            lock (_window_mutex) {
                _deliver_window--;
                Logger.Debug("tor_stream::decrement_deliver_window() [ _deliver_window = {0} ]", _deliver_window);
            }
        }

        internal bool ConsiderSendingSendme()
        {
            lock(_window_mutex) {
                if (_deliver_window > (window_start - window_increment)) {
                    Logger.Debug("tor_stream::consider_sending_sendme(): false");
                    return false;
                }

                // we're currently flushing immediatelly upon write,
                // therefore there is no need to check unflushed cell count,
                // because it's always 0.
                //
                // if (unflushed_cell_count >= window_max_unflushed)
                // {
                //   return false;
                // }

                _deliver_window += window_increment;
                Logger.Debug("tor_stream::consider_sending_sendme(): true");
                return true;
            }
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

        private const int window_start = 500;
        private const int window_increment = 50;
        private const int window_max_unflushed = 10;

        private ushort _stream_id;
        private Circuit _circuit;
        private int _deliver_window = window_start;
        private int _package_window = window_start;
        private Mutex _window_mutex = new Mutex();
        private List<byte> _buffer = new List<byte>();
        private Mutex _buffer_mutex = new Mutex();
        private StreamState _state = StreamState.connecting;
        private AutoResetEvent _stateChangeEvent = new AutoResetEvent(false);

        internal enum StreamState
        {
            none,
            connecting,
            ready,
            destroyed,
        }
    }
}
