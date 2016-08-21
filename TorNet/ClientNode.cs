using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TorNet.Tor;

namespace TorNet
{
    /// <summary>This class is the main one for clients implementations.</summary>
    public class ClientNode : IDisposable
    {
        public ClientNode()
        {
            _consensus = Consensus.Fetch(RetrievalOptions.DoNotUseCache);
        }

        ~ClientNode()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing) { GC.SuppressFinalize(this); }
            if (null != _circuit) { _circuit.Dispose(); }
        }

        public void ExtendTo(string onion_router_name)
        {
            OnionRouter router = _consensus.GetRouter(onion_router_name);

            if (null == _circuit) {
                _socket.Connect(router);
                _circuit = _socket.CreateCircuit();
            }
            else { _circuit.Extend(router); }
        }

    //mini::string
    //http_get(
    //  const mini::string_ref url
    //  )
    //{
    //    mini::tor::tor_stream* stream = nullptr;
    //    mini::string result;

    //    mini::string url_string = url;

    //    mini_info("tor_client::http_get() fetching [%s]", url_string.get_buffer());
    //    if (url_string.starts_with("http://"))
    //    {
    //        url_string = url_string.substring(7);
    //    }

    //    if (url_string.contains("/") == false)
    //    {
    //        url_string += "/";
    //    }

    //    mini::string_collection url_parts = url_string.split("/", 1);
    //    mini::string host = url_parts[0];
    //    mini::string path = url_parts[1];
    //    uint16_t port = 80;

    //    if (host.ends_with(".onion"))
    //    {
    //        mini::string onion = host.substring(0, host.get_size() - 6);

    //        stream = _circuit->create_onion_stream(onion, port);
    //    }
    //    else
    //    {
    //        extend_to("colocall321");

    //        stream = _circuit->create_stream(host, port);
    //    }

    //    mini::string req = "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\n\r\n";
    //    stream->write(req.get_buffer(), req.get_size());

    //    mini::io::stream_reader sr(*stream);
    //    result = sr.read_string_to_end();

    //    delete stream;

    //    return result;
    //}

        private Consensus _consensus;
        private TorSocket _socket = new TorSocket();
        private Circuit _circuit = null;
    }
}
