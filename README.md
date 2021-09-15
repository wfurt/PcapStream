# PcapStream

This is pcap(like) stream writer. It implements Stream interface and it is meant to be used as layer between application - like HttpClient - and actual transport stream. It will write all data read and writtent in format readable by tcpdump and Wireshark so it is easier to debug binary protocols or data wrappet in encrypted stream.

For HttpCLient the base use case is like 
```c#
  using var capture = new NetCapture($"{host}.pcap");

  var handler = new SocketsHttpHandler();
  handler.PlaintextStreamFilter = (context, token) => 
  { 
    return new ValueTask<Stream>(capture.AddStream(context.PlaintextStream)); 
  };
  using (HttpClient client = new HttpClient(handler))
  {
      ....
  }
```

It will try to detect transport parameters, add IP and TCP headers and it will write each Read or Write as a "packet". If transport IPEndpoints cannot be determined, it will use `127.0.0.1` addresses and generated TCP ports. IPEndpoiunt can also be handed explicitly to `AddStream` method. 
To make decoding easier, PcapStream will add 8400 to detected destination port. With that, connection to port 443 will be shown as 8843 in capture file. Without it Wireshark will have problems decoding the stream. 8843 is not used by well known protocos and it easy to set a default rule and decode 8843 automaticaly as HTTP. (or what ever). This behavir can be changed by passing `portOffset: 0` to `AddStream`.

```c#
namespace System.Net
{
    public class PcapStream : Stream
    {
        ...
    }
    
    public class NetCapture : IDisposable
    {
        public NetCapture(string fileName);
        public NetCapture(Stream stream);
        public PcapStream AddStream(Stream stream, IPEndPoint? localEndPoint = null, IPEndPoint? remoteEndPoint = null, int portOffset = defaultPortOffset)
    }
}
```

NuGet package available https://www.nuget.org/packages/PcapStream/

# TODO list and BUGS:
- TCP Ack needs more work
  - This works now for simple and reasonably small request/responses
  - For large unidirectional streams we will need to inject extra ACK packets to keep Wireshark calculations happy
- no checksums
  - neither IP headers nor TCP has checksum fields filled
  - that seems OK at the moment as Wireshark assumes HW support and does not complain much
- needs more testing
  
