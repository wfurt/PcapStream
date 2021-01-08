using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace PCapStreamTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string host = "google.com";
            if (args.Length > 0)
            {
                host = args[0];
            }

            using var capture = new NetCapture($"{host}.pcap");

            var handler = new SocketsHttpHandler();
            handler.PlaintextStreamFilter = (context, token) => { return new ValueTask<Stream>(capture.AddStream(context.PlaintextStream)); };
            using (HttpClient client = new HttpClient(handler))
            {
                var message = new HttpRequestMessage(HttpMethod.Get, new Uri($"https://{host}/"));
                message.Version = args.Length > 1 ? new Version(2, 0) : new Version(1, 1);
                //  message.VersionPolicy = HttpVersionPolicy.RequestVersionExact;

                HttpResponseMessage response = await client.SendAsync(message);
                Console.WriteLine(response);
            }
        }
    }
}
