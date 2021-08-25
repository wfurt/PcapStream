using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace System.Net
{
    public class PcapStream : Stream
    {
        private Stream _innerStream;
        internal Stream InnerStream => _innerStream;

        private readonly int localIP4;
        private readonly int remoteIP4;

        private byte[]? localIP6;
        private byte[]? remoteIP6;

        private readonly short localPort;
        private readonly short remotePort;
        private readonly int _portOffset;
        private readonly NetCapture _pcap;
        private readonly bool useIPv6;

        private long localSequence;
        private long remoteSequence;
        private Packet4 _packet4;
        private Packet6 _packet6;

        [StructLayout(LayoutKind.Sequential)]
        private struct PacketHeader
        {
            public uint ts_sec;         /* timestamp seconds */
            public uint ts_usec;        /* timestamp microseconds */
            public uint incl_len;       /* number of octets of packet saved in file */
            public uint orig_len;       /* actual length of packet */
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IPv4Header
        {
            public byte VersionAndLength;
            public byte TOS;
            public ushort TotalLength;
            private int Unused;
            public byte TTL;
            public byte Protocol;
            public ushort Checksum;
            public int src;
            public int dst;

            internal IPv4Header(IPAddress srcIP, IPAddress dstIP)
            {
                VersionAndLength = 0x45;
                TOS = 0;
                Checksum = TotalLength = 0;
                Unused = 0;
                TTL = 64;
                Protocol = 6;
#pragma warning disable 0618
                src = (int)srcIP.Address;
                dst = (int)dstIP.Address;
#pragma warning restore 0618
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct IPv6Header
        {
            public byte VersionAndClass;
            public byte Class2;
            public ushort Flow;
            public ushort PayloadLength;
            public byte NextHeader;
            public byte HopLimit;
            public fixed byte src[16];
            public fixed byte dst[16];

            internal IPv6Header(IPAddress srcIP, IPAddress dstIP)
            {
                VersionAndClass = 0x60;
                Class2 = 0;
                PayloadLength = Flow = 0;
                NextHeader = 6;
                HopLimit = 64;
            }
        }

        [Flags]
        internal enum TcpFlags : byte
        {
            Fin = 1,
            Syn = 2,
            Rst = 4,
            Psh = 8,
            Ack = 16,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TcpHeader
        {
            public short sport;
            public short dport;
            public uint SequenceNumber;
            public uint AcknowledgmentNumber;
            public byte Offset;
            public TcpFlags Flags;
            public ushort WindowSize;
            public ushort Checksum;
            public ushort UrgentPointer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Packet4
        {
            public PacketHeader packetHeader;
            public int link;
            public IPv4Header ipHeader;
            public TcpHeader tcpHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Packet6
        {
            public PacketHeader packetHeader;
            public int link;
            public IPv6Header ipHeader;
            public TcpHeader tcpHeader;
        }

        private unsafe void WriteTcpPacket(TcpFlags flags, ReadOnlySpan<byte> data, bool isResponse = false)
        {
            lock (_pcap)
            {
                ref PacketHeader packetHeader = ref (useIPv6 ? ref _packet6.packetHeader : ref _packet4.packetHeader);
                ref TcpHeader tcpHeader = ref (useIPv6 ? ref _packet6.tcpHeader : ref _packet4.tcpHeader);

                long now = Environment.TickCount64;
                packetHeader.ts_sec = (uint)(now / 10_0000);
                packetHeader.incl_len = (uint)(4 + (useIPv6 ? sizeof(IPv6Header) : sizeof(IPv4Header)) + sizeof(TcpHeader) + data.Length);
                packetHeader.orig_len = packetHeader.incl_len;

                if (useIPv6)
                {
                    _packet6.ipHeader.PayloadLength = (ushort)IPAddress.HostToNetworkOrder((short)(sizeof(TcpHeader) + data.Length));
                    fixed (byte* ptr = _packet6.ipHeader.src)
                    {
                        if (isResponse)
                        {
                            remoteIP6.CopyTo(new Span<byte>(ptr, remoteIP6!.Length));
                        }
                        else
                        {
                            localIP6.CopyTo(new Span<byte>(ptr, localIP6!.Length));
                        }
                    }

                    fixed (byte* ptr = _packet6.ipHeader.dst)
                    {
                        if (isResponse)
                        {
                            localIP6.CopyTo(new Span<byte>(ptr, localIP6!.Length));
                        }
                        else
                        {
                            remoteIP6.CopyTo(new Span<byte>(ptr, remoteIP6!.Length));
                        }
                    }
                }
                else
                {
                    _packet4.ipHeader.src = isResponse ? remoteIP4 : localIP4;
                    _packet4.ipHeader.dst = isResponse ? localIP4 : remoteIP4;
                    _packet4.ipHeader.TotalLength = (ushort)IPAddress.HostToNetworkOrder((short)(sizeof(IPv4Header) + sizeof(TcpHeader) + data.Length));
                }

                tcpHeader.Flags = flags;

                ref long sequence = ref localSequence;
                long ack;
                if (isResponse)
                {
                    tcpHeader.sport = remotePort;
                    tcpHeader.dport = localPort;
                    sequence = ref remoteSequence;
                    ack = localSequence + 1;
                    ack = localSequence;
                }
                else
                {
                    tcpHeader.sport = localPort;
                    tcpHeader.dport = remotePort;
                    sequence = ref localSequence;
                    ack = remoteSequence;
                }
  
                tcpHeader.SequenceNumber = (uint)IPAddress.HostToNetworkOrder((int)sequence);
                sequence += data.Length;
                if (sequence > uint.MaxValue)
                {
                    // Wrap the number
                    sequence -= uint.MaxValue;
                }

                if (ack > uint.MaxValue)
                {
                    ack -= uint.MaxValue;
                }

                if ((flags & TcpFlags.Syn) == TcpFlags.Syn)
                {
                    sequence++;
                }

                if ((flags & TcpFlags.Ack) == TcpFlags.Ack)
                {
                    tcpHeader.AcknowledgmentNumber = (uint)IPAddress.HostToNetworkOrder((int)ack);
                }


                // TBD: fix up Checksum;

                if (useIPv6)
                {
                    fixed (void* ptr = &_packet6)
                    {
                        _pcap.fs.Write(new ReadOnlySpan<byte>(ptr, sizeof(Packet6)));

                    }
                }
                else
                {
                    fixed (void* ptr = &_packet4)
                    {
                        _pcap.fs.Write(new ReadOnlySpan<byte>(ptr, sizeof(Packet4)));

                    }
                }

                if (data.Length > 0)
                {
                    _pcap.fs.Write(data);
                }
            }
        }

        internal unsafe PcapStream(NetCapture pcap, Stream innerStream, IPEndPoint localEndPoint, IPEndPoint remoteEndPoint, int portOffset)
        {
            _pcap = pcap;
            _innerStream = innerStream;
            _portOffset = portOffset;

            if (localEndPoint.AddressFamily == AddressFamily.InterNetworkV6 && !localEndPoint.Address.IsIPv4MappedToIPv6)
            {
                useIPv6 = true;
                _packet6.link = 30;

                _packet6.ipHeader = new IPv6Header(localEndPoint.Address, remoteEndPoint.Address);
                _packet6.ipHeader.Flow = (ushort)_pcap.rnd.Next(0, ushort.MaxValue);

                localIP6 = new byte[16];
                remoteIP6 = new byte[16];
                int len;
                localEndPoint.Address.TryWriteBytes(localIP6, out len);
                remoteEndPoint.Address.TryWriteBytes(remoteIP6, out len);
            }
            else
            {
                _packet4.link = 2;
                _packet4.ipHeader = new IPv4Header(localEndPoint.Address.MapToIPv4(), remoteEndPoint.Address.MapToIPv4());
#pragma warning disable 0618
                localIP4 = (int)localEndPoint.Address.MapToIPv4().Address;
                remoteIP4 = (int)remoteEndPoint.Address.MapToIPv4().Address;
#pragma warning restore 0618
            }


            localPort = IPAddress.HostToNetworkOrder((short)localEndPoint.Port);
            remotePort = IPAddress.HostToNetworkOrder((short)(remoteEndPoint.Port + _portOffset));
            localSequence = _pcap.rnd.Next(int.MaxValue);
            remoteSequence = _pcap.rnd.Next(int.MaxValue);

            ref TcpHeader tcpHeader = ref (useIPv6 ? ref _packet6.tcpHeader : ref _packet4.tcpHeader);
            tcpHeader.Offset = 0x50;
            tcpHeader.WindowSize = ushort.MaxValue;

            // fake handsake
            WriteTcpPacket(TcpFlags.Syn, ReadOnlySpan<byte>.Empty);
            WriteTcpPacket(TcpFlags.Syn|TcpFlags.Ack, ReadOnlySpan<byte>.Empty, true);
            WriteTcpPacket(TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
        }

        protected override void Dispose(bool disposing)
        {
            // fake close
            WriteTcpPacket(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
            WriteTcpPacket(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty, true);

            if (disposing)
            {
                InnerStream.Dispose();
            }

            base.Dispose(disposing);
        }

        public override bool CanSeek => false;

        public override bool CanRead => InnerStream.CanRead;

        public override bool CanTimeout => InnerStream.CanTimeout;

        public override bool CanWrite => InnerStream.CanWrite;

        public override long Position
        {
            get
            {
                return InnerStream.Position;
            }

            set
            {
                InnerStream.Position = value;
            }
        }

        public override void SetLength(long value) => InnerStream.SetLength(value);

        public override long Length => InnerStream.Length;

        public override void Flush() => InnerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => InnerStream.FlushAsync(cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => InnerStream.Seek(offset, origin);

        public override int Read(byte[] buffer, int offset, int count) => Read(new Span<byte>(buffer, offset, count));

        public override int Read(Span<byte> buffer)
        {
            int readLength = InnerStream.Read(buffer);
            WriteTcpPacket(TcpFlags.Psh | TcpFlags.Ack, buffer.Slice(0, readLength), isResponse: true);
            return readLength;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => ReadAsync(new Memory<byte>(buffer, offset, count)).AsTask();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ValueTask<int> task = InnerStream.ReadAsync(buffer, cancellationToken);

            if (!task.IsCompletedSuccessfully)
            {
                return InternalReadAsync(task, buffer, cancellationToken);
            }

            int readLength = (int)task.Result;
            WriteTcpPacket(TcpFlags.Psh | TcpFlags.Ack, buffer.Span.Slice(0, readLength), isResponse: true);

            return task;

            async ValueTask<int> InternalReadAsync(ValueTask<int> task, Memory< byte> buffer, CancellationToken cancellationToken)
            {
                int readLength = await task;
                WriteTcpPacket(TcpFlags.Psh | TcpFlags.Ack, buffer.Span.Slice(0, readLength), isResponse: true);

                return readLength;
            }
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(new ReadOnlySpan<byte>(buffer, offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            WriteTcpPacket(TcpFlags.Psh | TcpFlags.Ack, buffer);
            InnerStream.Write(buffer);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => WriteAsync(new ReadOnlyMemory<byte>(buffer, offset, count)).AsTask();
        
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            WriteTcpPacket(TcpFlags.Psh | TcpFlags.Ack, buffer.Span);
            return InnerStream.WriteAsync(buffer, cancellationToken);
        }
    }

    public class NetCapture : IDisposable
    {
        private const uint magicNumber = 0xa1b2c3d4;
        private const short majorVersion = 2;
        private const short minorVersion = 4;
        private const int defaultPortOffset = 8400;

        [StructLayout(LayoutKind.Sequential)]
        private struct globalHeader
        {
            public uint magic_number;   /* magic number */
            public short version_major;  /* major version number */
            public short version_minor;  /* minor version number */
            public int thiszone;       /* GMT to local correction */
            public int sigfigs;        /* accuracy of timestamps */
            public int snaplen;        /* max length of captured packets, in octets */
            public int network;        /* data link type */
        }

        internal readonly Stream fs;
        internal readonly Random rnd;
        private int streamCounter = 1024;
        private PropertyInfo? innerStream;

        public unsafe NetCapture(string fileName) : this(new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite))
        {
        }

        public unsafe NetCapture(Stream stream)
        {
            fs = stream;
            rnd = new Random();
            globalHeader header = new globalHeader()
            {
                magic_number = magicNumber,
                version_major = majorVersion,
                version_minor = minorVersion,
                thiszone = 0,
                sigfigs = 0,
                snaplen = 65535,
                network = 0
            };

            fs.Write(new Span<byte>(&header, sizeof(globalHeader)));
        }

        public PcapStream AddStream(Stream stream, IPEndPoint? localEndPoint = null, IPEndPoint? remoteEndPoint = null, int portOffset = defaultPortOffset)
        {
            if (localEndPoint is null || remoteEndPoint is null)
            {
                NetworkStream? ns = null;

                // Check if we have NetworkStream with IPEndpoint.
                // If so, we can get basic info from there.
                if (stream is SslStream)
                {
                    if (innerStream is null)
                    {
                        // Grab InnerStream so we can get handle on the actual IO.
                        innerStream = stream.GetType().GetProperty("InnerStream", BindingFlags.NonPublic | BindingFlags.NonPublic | BindingFlags.Instance);
                    }

                    if (innerStream is not null)
                    {
                        var inner = innerStream.GetValue(stream);
                        if (inner is NetworkStream)
                        {
                            ns = (NetworkStream)inner;
                        }
                    }
                }
                else if (stream is NetworkStream)
                {
                    ns = stream as NetworkStream;
                }

                if (ns != null)
                {
                    EndPoint localEP = ns.Socket.LocalEndPoint!;
                    EndPoint remoteEP = ns.Socket.RemoteEndPoint!;

                    if(localEP is IPEndPoint)
                    {
                        localEndPoint = (IPEndPoint)localEP;
                    }

                    if (remoteEP is IPEndPoint)
                    {
                        remoteEndPoint = (IPEndPoint)remoteEP;
                    }
                }

                // We failed to get L3/4 info. We will need to synthetize it.
                if (localEndPoint is null || remoteEndPoint is null)
                {
                    localEndPoint = new IPEndPoint(IPAddress.Loopback, streamCounter++);
                    remoteEndPoint = new IPEndPoint(IPAddress.Loopback, streamCounter++);
                }

            }

            return new PcapStream(this, stream, localEndPoint, remoteEndPoint, portOffset);
        }

        public void Dispose()
        {
            fs.Flush();
            fs.Close();
        }
    }
}
