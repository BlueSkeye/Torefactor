using System;
using System.Collections.Generic;

using TorNet.Cryptography;

namespace TorNet.Tor
{
    internal partial class Consensus
    {
        internal class Parser
        {
            static Parser()
            {
                router_status_flags = new List<string>();
                router_status_flags.Add("Authority");
                router_status_flags.Add("BadExit");
                router_status_flags.Add("Exit");
                router_status_flags.Add("Fast");
                router_status_flags.Add("Guard");
                router_status_flags.Add("HSDir");
                router_status_flags.Add("Named");
                router_status_flags.Add("NoEdConsensus");
                router_status_flags.Add("Stable");
                router_status_flags.Add("Running");
                router_status_flags.Add("Unnamed");
                router_status_flags.Add("Valid");
                router_status_flags.Add("V2Dir");
            }

            OnionRouter.status_flags string_to_status_flags(IEnumerable<string> splitted)
            {
                OnionRouter.status_flags result = OnionRouter.status_flags.none;
                foreach (string flag_string in splitted) {
                    int index = router_status_flags.IndexOf(flag_string);
                    if (-1 != index) {
                        OnionRouter.status_flags flag = (OnionRouter.status_flags)(1 << index);
                        result |= flag;
                    }
                }
                return result;
            }

            internal void Parse(Consensus consensus, string content, bool reject_invalid = true)
            {
                string[] lines = content.Split('\n');
                document_location current_location = document_location.preamble;
                OnionRouter current_router = null;

                foreach (string line in lines) {
                    string[] splitted_line = line.Split(' ');

                    // move the location if we are at the router status entries.
                    if ((1 == splitted_line[0].Length) && ('r' == splitted_line[0][0])) {
                        current_location = document_location.router_status_entry;
                    }
                    else if ("directory-footer" == splitted_line[0]) {
                        current_location = document_location.directory_footer;
                    }

                    switch (current_location) {
                        case document_location.preamble:
                            if ("valid-until" == splitted_line[0]) {
                                consensus._valid_until =
                                    Helpers.ParseTime(splitted_line[1] + " " + splitted_line[2]);

                                if (reject_invalid && consensus._valid_until < DateTime.Now) {
                                    return;
                                }
                            }
                            break;
                        case document_location.router_status_entry:
                            // check if the control word has at least one letter.
                            if (1 > splitted_line[0].Length) { break; }
                            Globals.Assert(splitted_line[0].Length == 1);

                            switch (splitted_line[0][0]) {
                                case 'r':
                                    // router.
                                    if (Enum.IsDefined(typeof(router_status_entry_r_type), (router_status_entry_r_type)splitted_line.Length)) {
                                        // next line.
                                        continue;
                                    }
                                    string identity_fingerprint = Base16.Encode(
                                        Base64.Decode(splitted_line[(int)router_status_entry_r_type.router_status_entry_r_identity]));
                                    current_router = new OnionRouter(consensus,
                                        splitted_line[(int)router_status_entry_r_type.router_status_entry_r_nickname],
                                        splitted_line[(int)router_status_entry_r_type.router_status_entry_r_ip],
                                        (ushort)(int.Parse(splitted_line[(int)router_status_entry_r_type.router_status_entry_r_or_port])),
                                        (ushort)(int.Parse(splitted_line[(int)router_status_entry_r_type.router_status_entry_r_dir_port])),
                                        identity_fingerprint);
                                    consensus._onion_router_map.Add(identity_fingerprint, current_router);
                                    break;
                                case 's':
                                    // flags.
                                    if (null != current_router) {
                                        current_router.Flags = string_to_status_flags(line.Split(' '));
                                    }
                                    break;
                            }
                            break;
                        case document_location.directory_footer:
                            // ignore directory footer.
                            return;
                    }
                }
            }

            private static readonly string[] preamble_control_words = new string[] {
            "valid-until" };
            private static readonly char[] router_status_entry_chars = new char[] {
            'r', 'a', 's', 'v', 'w', 'p', };
            private static readonly List<string> router_status_flags;

            // dir-spec.txt
            // 3.4.1.
            // Status documents contain a preamble, an authority section, a list of
            // router status entries, and one or more footer signature, in that order.
            internal enum document_location
            {
                preamble,
                router_status_entry,
                directory_footer
            }

            // preamble.
            internal enum preamble_type
            {
                preamble_valid_until
            }

            // router status entry.
            internal enum router_status_entry_type
            {
                router_status_entry_r,
                router_status_entry_a,
                router_status_entry_s,
                router_status_entry_v,
                router_status_entry_w,
                router_status_entry_p,
            };

            internal enum router_status_entry_r_type
            {
                // start counting from 1,
                // because there is the "r" control word
                // on the index 0.
                router_status_entry_r_nickname = 1,
                router_status_entry_r_identity,
                router_status_entry_r_digest,
                router_status_entry_r_publication_date,
                router_status_entry_r_publication_time,
                router_status_entry_r_ip,
                router_status_entry_r_or_port,
                router_status_entry_r_dir_port,

                // router_status_entry_r_item_count = 9
                router_status_entry_r_item_count,
            }

            internal enum router_status_entry_s_type
            {
                router_status_entry_s_none = 0x0000,
                router_status_entry_s_authority = 0x0001,
                router_status_entry_s_bad_exit = 0x0002,
                router_status_entry_s_exit = 0x0004,
                router_status_entry_s_fast = 0x0008,
                router_status_entry_s_guard = 0x0010,
                router_status_entry_s_hsdir = 0x0020,
                router_status_entry_s_named = 0x0040,
                router_status_entry_s_no_ed_consensus = 0x0080,
                router_status_entry_s_stable = 0x0100,
                router_status_entry_s_running = 0x0200,
                router_status_entry_s_unnamed = 0x0400,
                router_status_entry_s_valid = 0x0800,
                router_status_entry_s_v2dir = 0x1000,
            }
        }
    }
}
