using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TorNet.Cryptography;
using TorNet.Tor.Parsers;

namespace TorNet.Tor.Parsers
{
    internal class HiddenServiceDescriptorParser
    {
        internal void parse(Consensus consensus, string descriptor)
        {
            string[] lines = descriptor.Split('\n');
            document_location current_location = document_location.control_word;
            string current_message = string.Empty;

            foreach (string line in lines) {
                // introduction-points
                if (line == control_words[(int)control_word_type.control_word_introduction_points]) {
                    current_location = document_location.introduction_points;
                    continue;
                }
                // -----BEGIN MESSAGE-----
                else if (line == control_words[(int)control_word_type.control_word_message_begin]) {
                    current_location = document_location.introduction_points_content;
                    continue;
                }
                // -----END MESSAGE-----
                else if (line == control_words[(int)control_word_type.control_word_message_end]) {
                    current_location = document_location.control_word;
                    break;
                }
                else if (current_location == document_location.introduction_points_content) {
                    current_message += line;
                }
            }
            // introduction points are base64 encoded.
            string introduction_point_descriptor_string =
                ASCIIEncoding.ASCII.GetString(Base64.Decode(current_message));

            // parse the introduction point descriptor.
            IntroductionPointParser parser = new IntroductionPointParser();
            parser.parse(consensus, introduction_point_descriptor_string);
            introduction_point_list = parser.introduction_point_list;
            parser.introduction_point_list = null;
        }

        internal List<OnionRouter> introduction_point_list = new List<OnionRouter>();

        // using control_word_list = stack_buffer<string_hash, 3>;
        private static readonly string[] control_words = new string[] {
            "introduction-points",
            "-----BEGIN MESSAGE-----",
            "-----END MESSAGE-----",
        };

        internal enum control_word_type
        {
            control_word_introduction_points,
            control_word_message_begin,
            control_word_message_end,
        }

        internal enum document_location
        {
            control_word,
            introduction_points,
            introduction_points_content,
        }
    }
}
