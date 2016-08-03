
using TorNet.Cryptography;

namespace TorNet.Tor.Parsers
{
    internal static class ServerDescriptorParser
    {
        internal enum document_location
        {
            control_word,
            onion_key,
            onion_key_content,
            signing_key,
            signing_key_content,
        }

        internal enum control_word_type
        {
            control_word_onion_key,
            control_word_signing_key,

            control_word_key_begin,
            control_word_key_end,
        }

        // using control_word_list = stack_buffer<string_hash, 4>;
        private static readonly string[] control_words = new string[] {
            "onion-key",
            "signing-key",
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----END RSA PUBLIC KEY-----",
        };

        internal static void Parse(OnionRouter router, string descriptor)
        {
            string[] lines = descriptor.Split('\n');
            document_location current_location = document_location.control_word;
            string current_key = null;

            foreach(string line in lines) {
                // onion-key
                if (line == control_words[(int)control_word_type.control_word_onion_key]) {
                    current_location = document_location.onion_key;
                    continue;
                }
                // signing-key
                if (line == control_words[(int)control_word_type.control_word_signing_key]) {
                    current_location = document_location.signing_key;
                    continue;
                }
                // -----BEGIN RSA PUBLIC KEY-----
                if (line == control_words[(int)control_word_type.control_word_key_begin])
                {
                    if (current_location == document_location.onion_key) {
                        current_location = document_location.onion_key_content;
                    }
                    else if (current_location == document_location.signing_key) {
                        current_location = document_location.signing_key_content;
                    }
                    continue;
                }
                // -----END RSA PUBLIC KEY-----
                if (line == control_words[(int)control_word_type.control_word_key_end]) {
                    if (current_location == document_location.onion_key_content) {
                        router.OnionKey = Base64.Decode(current_key);
                    }
                    else if (current_location == document_location.signing_key_content) {
                        router.SigningKey = Base64.Decode(current_key);
                    }
                    current_location = document_location.control_word;
                    current_key = null;
                }
                else if (current_location == document_location.onion_key_content ||
                         current_location == document_location.signing_key_content)
                {
                    current_key += line;
                }
            }
        }
    }
}
