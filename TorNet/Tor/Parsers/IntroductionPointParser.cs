using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TorNet.Cryptography;

namespace TorNet.Tor.Parsers
{
    internal class IntroductionPointParser
    {
        // using control_word_list = stack_buffer<string_hash, 4>;
        internal void parse(ConsensusOrVote consensus, string descriptor)
        {
            string[] lines = descriptor.Split('\n');
            document_location current_location = document_location.control_word;
            OnionRouter current_router = null;
            string current_key = null;

            foreach (string line in lines) {
                string[] splitted_line = line.Split(' ');
                string control_word_hash = splitted_line[0];

                // introduction-point
                if (control_word_hash == control_words[(int)control_word_type.control_word_introduction_point]) {
                    string identity_fingerprint = Base16.Encode(Base32.decode(splitted_line[1]));
                    current_router = consensus.get_onion_router_by_identity_fingerprint(identity_fingerprint);
                    continue;
                }
                // service-key
                if (control_word_hash == control_words[(int)control_word_type.control_word_service_key]) {
                    current_location = document_location.service_key;
                    continue;
                }
                // -----BEGIN RSA PUBLIC KEY-----
                if (line == control_words[(int)control_word_type.control_word_key_begin] && current_location == document_location.service_key) {
                    current_location = document_location.service_key_content;
                    continue;
                }
                // -----END RSA PUBLIC KEY-----
                if (line == control_words[(int)control_word_type.control_word_key_end] && current_location == document_location.service_key_content) {
                    if (null != current_router) {
                        current_router.ServiceKey = Base64.Decode(current_key);
                        introduction_point_list.Add(current_router);
                    }
                    current_location = document_location.control_word;
                    current_key = null;
                }
                else if (current_location == document_location.service_key_content) {
                    current_key += line;
                }
            }
        }

        private static readonly string[] control_words = new string[] {
            "introduction-point",
            "service-key",
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----END RSA PUBLIC KEY-----",
        };

        internal List<OnionRouter> introduction_point_list = new List<OnionRouter>();

        internal enum document_location
        {
            control_word,
            service_key,
            service_key_content,
        }

        internal enum control_word_type
        {
            control_word_introduction_point,
            control_word_service_key,
            control_word_key_begin,
            control_word_key_end,
        }
    }
}
