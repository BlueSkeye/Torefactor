using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace TorNet.IO
{
    internal class StreamWrapper
    {
        public StreamWrapper(Stream stream, Endianness endianness = Globals.DefaultEndianness)
        {
            _stream = stream;
            _endianness = endianness;
        }

        //    template<
        //      typename T,
        //      typename = std::enable_if_t<std::is_pod_v<T>>
        //    >
        //    T
        //read(
        //  void
        //  )
        //    {
        //        T result = T();
        //        size_t bytes_read = read(result);

        //        return result;
        //    }

        //    template<
        //      typename T,
        //      typename = std::enable_if_t<std::is_pod_v<T>>
        //    >
        //    size_t
        //read(
        //  T& result
        //  )
        //    {
        //        size_t bytes_read = _stream.read(&result, sizeof(result));

        //        if (_endianness != current_endianness)
        //        {
        //            result = swap_endianness(result);
        //        }

        //        return bytes_read;
        //    }

        //    template<
        //      typename T,
        //      size_t N,
        //      typename = std::enable_if_t<std::is_pod_v<T>>
        //    >
        //    size_t
        //read(
        //  T (&result)[N]
        //  )
        //{
        //  return read(result, N* sizeof(T));
        //}

        internal int Read(byte[] buffer)
        {
            return Read(buffer, buffer.Length);
        }

        internal int Read(byte[] buffer, int size)
        {
            return _stream.Read(buffer, 0, size);
        }

        internal byte ReadByte()
        {
            byte[] buffer = new byte[sizeof(byte)];
            Read(buffer);
            return buffer[0];
        }

        internal ushort ReadUInt16()
        {
            byte[] buffer = new byte[sizeof(ushort)];
            Read(buffer);
            return buffer.ToUInt16();
        }

        internal uint ReadUInt32()
        {
            byte[] buffer = new byte[sizeof(uint)];
            Read(buffer);
            return buffer.ToUInt32();
        }

        //size_t
        //read(
        //  mutable_byte_buffer_ref buffer
        //  )
        //{
        //    return _stream.read(buffer.get_buffer(), buffer.get_size());
        //}

        internal int Write(uint value)
        {
            uint value_to_write = value;
            if (Globals.DefaultEndianness != _endianness) {
                value_to_write = value.SwapEndianness();
            }
            _stream.Write(value_to_write.ToArray(), 0, sizeof(uint));
            return sizeof(uint);
        }

        internal int Write(ushort value)
        {
            uint value_to_write = value;
            if (Globals.DefaultEndianness != _endianness) {
                value_to_write = value.SwapEndianness();
            }
            _stream.Write(value_to_write.ToArray(), 0, sizeof(ushort));
            return sizeof(ushort);
        }

        internal int Write(string value)
        {
            return Write(ASCIIEncoding.ASCII.GetBytes(value));
        }

        internal int Write(byte value)
        {
            _stream.Write(new byte[] { value }, 0, sizeof(byte));
            return sizeof(byte);
        }

        internal int Write(byte[] value)
        {
            _stream.Write(value, 0, value.Length);
            return sizeof(byte);
        }

        internal Stream Stream
        {
            get { return _stream; }
        }

        internal bool IsEndOfStream
        {
            get { return _stream.Position == _stream.Length; }
        }

        private Stream _stream;
        private Endianness _endianness;
    }
}
