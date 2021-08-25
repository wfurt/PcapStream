using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace PcapStreamTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string dst = "https://h2o.examp1e.net/";
            if (args.Length > 0)
            {
                dst = args[0];
            }

            var uri = new Uri(dst);

            using var capture = new NetCapture($"{uri.Host}.pcap");

            var handler = new SocketsHttpHandler();
            handler.PlaintextStreamFilter = (context, token) =>
            {
                return new ValueTask<Stream>(capture.AddStream(context.PlaintextStream));
            };

            using (HttpClient client = new HttpClient(handler))
            {
                var message = new HttpRequestMessage(HttpMethod.Get, uri);
                message.Version = args.Length > 1 ? new Version(2, 0) : new Version(1, 1);
                message.VersionPolicy = HttpVersionPolicy.RequestVersionExact;

                HttpResponseMessage response = await client.SendAsync(message);
                Console.WriteLine(response);
            }
        }
    }
}
