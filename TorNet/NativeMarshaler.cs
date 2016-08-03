using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TorNet
{
    internal class NativeMarshaler
    {
        internal NativeMarshaler()
        {
            return;
        }

        internal int this[int chunkId]
        {
            get { return _offsetPerChunk[chunkId]; }
        }

        internal int this[object owner]
        {
            get
            {
                int result;
                return _chunksPerOwner.TryGetValue(owner, out result)
                    ? result
                    : NonExistingChunkId;
            }
        }

        private int AlignChunk(int boundary, int chunkId)
        {
            int currentOffset;
            try { currentOffset = _offsetPerChunk[chunkId]; }
            catch { throw; }
            int modulus = currentOffset % boundary;
            if (0 == modulus) { return currentOffset; }
            int delta = boundary - modulus;
            currentOffset += delta;
            _offsetPerChunk[chunkId] = currentOffset;
            return currentOffset;
        }

        private static uint AlignOffset(int boundary, uint offset)
        {
            if (0 >= boundary) { throw new ArgumentException(); }
            uint modulus = offset % (uint)boundary;
            if (0 == modulus) { return offset; }
            uint delta = (uint)boundary - modulus;
            return offset + delta;
        }

        internal bool DoesChunckExist(int candidate)
        {
            return _offsetPerChunk.ContainsKey(candidate);
        }

        internal IntPtr Finalize(out int bufferSize)
        {
            if (IntPtr.Zero == _nativeBuffer) {
                // First time finalization. Allocate the native buffer and return
                // a null pointer thus indicating to continue serializing. From
                // now on we will effectively write to the freshly allocated buffer.
                int chunksCount = _offsetPerChunk.Count;
                uint cumulatedOffset = 0;
                for(int index = 0; index < chunksCount; index++) {
                    uint currentOffset = cumulatedOffset;
                    uint alignedOffset = AlignOffset(IntPtr.Size, currentOffset);
                    int chunkSize = _offsetPerChunk[index];
                    _offsetPerChunk[index] = (int)alignedOffset;
                    cumulatedOffset = (uint)chunkSize + alignedOffset;
                }
                cumulatedOffset = AlignOffset(IntPtr.Size, cumulatedOffset);
                _nativeBufferSize = (int)cumulatedOffset;
                _nativeBuffer = Marshal.AllocCoTaskMem(_nativeBufferSize);
                _nativeBuffer.Zeroize(_nativeBufferSize);
                bufferSize = _nativeBufferSize;
                return IntPtr.Zero;
            }
            // Finalize a second time. Serialization is over. Hand off the native
            // buffer to the caller and reinitialize the marshaller.
            try {
                bufferSize = _nativeBufferSize;
                return _nativeBuffer;
            }
            finally {
                _nativeBuffer = IntPtr.Zero;
                _offsetPerChunk.Clear();
                _chunksPerOwner.Clear();
            }
        }

        internal int NewChunk(object owner = null)
        {
            if ((null != owner) && _chunksPerOwner.ContainsKey(owner)) {
                throw new InvalidOperationException();
            }
            int result = _offsetPerChunk.Count;
            _offsetPerChunk[result] = 0;
            if (null != owner) {
                _chunksPerOwner.Add(owner, result);
            }
            return result;
        }

        internal static IntPtr ReadIntPtr(IntPtr from, ref uint offset)
        {
            offset = AlignOffset(IntPtr.Size, offset);
            try { return Marshal.ReadIntPtr(from, (int)offset); }
            finally { offset += (uint)IntPtr.Size; }
        }

        internal static uint ReadUint32(IntPtr from, ref uint offset)
        {
            offset = AlignOffset(sizeof(uint), offset);
            try { return (uint)Marshal.ReadInt32(from, (int)offset); }
            finally { offset += sizeof(uint); }
        }

        internal void Write(IntPtr value, int chunkId)
        {
            Write(value, IntPtr.Size, chunkId, Marshal.WriteIntPtr);
            return;
        }

        internal void Write(byte[] value, int chunkId)
        {
            int offset = AlignChunk(sizeof(uint), chunkId);
            if ((IntPtr.Zero != _nativeBuffer) && (null != value)) {
                Marshal.Copy(value, 0, _nativeBuffer + offset, value.Length);
            }
            offset += (null == value) ? 0 : value.Length;
            _offsetPerChunk[chunkId] = offset;
            return;
        }

        internal void Write(int value, int chunkId)
        {
            Write(value, sizeof(int), chunkId, Marshal.WriteInt32);
            return;
        }

        internal void Write(uint value, int chunkId)
        {
            Write((int)value, chunkId);
            return;
        }

        internal void WriteRelativePointer(int displacement, int chunkId)
        {
            Write(_nativeBuffer + displacement, chunkId);
            return;
        }

        private void Write<T>(T value, int itemSize, int chunkId, WriterDelegate<T> writer)
        {
            int offset = AlignChunk(itemSize, chunkId);
            if (IntPtr.Zero != _nativeBuffer) {
                writer(_nativeBuffer, offset, value);
            }
            offset += itemSize;
            _offsetPerChunk[chunkId] = offset;
            return;
        }

        private delegate void WriterDelegate<T>(IntPtr at, int offset, T value);

        internal const int NonExistingChunkId = -1;
        private Dictionary<object, int> _chunksPerOwner = new Dictionary<object, int>();
        private IntPtr _nativeBuffer;
        private int _nativeBufferSize;
        private SortedList<int, int> _offsetPerChunk = new SortedList<int, int>();
    }
}
