using System;
using System.Collections.Generic;

using TorNet.Cryptography;
using TorNet.Tor.Parsers;

namespace TorNet.Tor
{
    internal partial class Consensus
    {
        internal class Parser : ConsensusAndVoteBaseParser
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

            private Parser(Consensus target)
                : base(DocumentType.Consensus, target)
            {
                return;
            }

            protected override void AssertStatus(string candidate)
            {
                if (candidate != "consensus") {
                    base.ParsingError("Expecting 'consensus' status. Found {0}.",
                        candidate);
                }
            }

            /// <summary>Parse the given consensus content and setup the consensus
            /// instance accordingly.</summary>
            /// <param name="consensus"></param>
            /// <param name="content"></param>
            /// <param name="rejectInvalid">true if the consensus must be rejected
            /// ifvalidty date eceeds current date. Notwithstanding this flag, any
            /// other malformation will trigger an exception.</param>
            internal static Consensus Parse(string content, bool rejectInvalid = true)
            {
                Consensus target = new Consensus();
                new Parser(target)._Parse(content);
                return target;
            }

            protected override void SetConsensusMethod(VotingMethod value)
            {
                _method = value;
            }

            OnionRouter.StatusFlags string_to_status_flags(IEnumerable<string> splitted)
            {
                OnionRouter.StatusFlags result = OnionRouter.StatusFlags.none;
                foreach (string flag_string in splitted) {
                    int index = router_status_flags.IndexOf(flag_string);
                    if (-1 != index) {
                        OnionRouter.StatusFlags flag = (OnionRouter.StatusFlags)(1 << index);
                        result |= flag;
                    }
                }
                return result;
            }

            //internal void Parse(Consensus consensus, string content, bool rejectInvalid = true)
            //{
            //    if (null == consensus) { throw new ArgumentNullException(); }
            //    _target = consensus;
            //    base.Parse(content, rejectInvalid);
            //    throw new NotImplementedException();

            //    string[] lines = content.Split('\n');
            //    DocumentLocation currentLocation = DocumentLocation.Preamble;
            //    OnionRouter current_router = null;

            //    try {
            //        foreach (string line in lines) {
            //            string[] currentLineItems = line.Split(' ');
            //            string currentLineKeyword = currentLineItems[0];

            //            // move the location if we are at the router status entries.
            //            if ("r" == currentLineKeyword) {
            //                currentLocation = DocumentLocation.RouterStatusEntry;
            //            }
            //            else if ("directory-footer" == currentLineKeyword) {
            //                currentLocation = DocumentLocation.DirectoryFooter;
            //            }

            //            switch (currentLocation) {
            //                case DocumentLocation.Preamble:
            //                    if ("valid-until" == currentLineKeyword) {
            //                        consensus._validUntilUTC =
            //                            Helpers.ParseTime(currentLineItems[1] + " " + currentLineItems[2]);

            //                        if (rejectInvalid && (DateTime.UtcNow > consensus._validUntilUTC)) {
            //                            throw new ParsingException("Invalid consensus : date exceeded {0}",
            //                                consensus._validUntilUTC);
            //                        }
            //                    }
            //                    break;
            //                case DocumentLocation.RouterStatusEntry:
            //                    // check if the control word has at least one letter.
            //                    if (1 > currentLineKeyword.Length) { break; }
            //                    Globals.Assert(1 == currentLineKeyword.Length);

            //                    switch (currentLineKeyword) {
            //                        case "r":
            //                            // router.
            //                            if (!Enum.IsDefined(typeof(RouterStatusProperty), (RouterStatusProperty)currentLineItems.Length)) {
            //                                // next line.
            //                                continue;
            //                            }
            //                            string identityFingerprint = Base16.Encode(
            //                                Base64.Decode(currentLineItems[(int)RouterStatusProperty.Identity]));
            //                            current_router = new OnionRouter(consensus,
            //                                currentLineItems[(int)RouterStatusProperty.Nickname],
            //                                currentLineItems[(int)RouterStatusProperty.IPAddress],
            //                                (ushort)(int.Parse(currentLineItems[(int)RouterStatusProperty.ORPort])),
            //                                (ushort)(int.Parse(currentLineItems[(int)RouterStatusProperty.DirectoryPort])),
            //                                identityFingerprint);
            //                            consensus._onionRouterMap.Add(identityFingerprint, current_router);
            //                            break;
            //                        case "s":
            //                            // flags.
            //                            if (null != current_router) {
            //                                current_router.Flags = string_to_status_flags(line.Split(' '));
            //                            }
            //                            break;
            //                    }
            //                    break;
            //                case DocumentLocation.DirectoryFooter:
            //                    // TODO : The footer is ignored in the base implementation.
            //                    // This is unacceptable because it contains the authoritative directories
            //                    // signatures. The consensus may be retrieved using a simple HTTP request
            //                    // that is easily forged.

            //                    // ignore directory footer.
            //                    currentLocation = DocumentLocation.Done;
            //                    return;
            //            }
            //        }
            //    }
            //    finally {
            //        if (DocumentLocation.Done != currentLocation) {
            //            throw new ParsingException("Invalid consensus ; last known state {0}",
            //                currentLocation);
            //        }
            //    }
            //}

            protected override void SetTarget(ConsensusOrVote candidate)
            {
                Consensus consensus = candidate as Consensus;
                if (null != _target) { WTF(); }
                if (null == consensus) { base.WTF(); }
                _target = consensus;
                return;
            }

            private VotingMethod _method;
            private Consensus _target;
            private static readonly string[] preamble_control_words = new string[] {
                "valid-until" };
            private static readonly char[] router_status_entry_chars = new char[] {
                'r', 'a', 's', 'v', 'w', 'p', };
            private static readonly List<string> router_status_flags;

            // dir-spec.txt
            // 3.4.1.
            // Status documents contain a preamble, an authority section, a list of
            // router status entries, and one or more footer signature, in that order.
            internal enum DocumentLocation
            {
                Preamble,
                RouterStatusEntry,
                DirectoryFooter,
                Done
            }

            // preamble.
            internal enum preamble_type
            {
                preamble_valid_until
            }

            // router status entry.
            internal enum RouterStatusEntryType
            {
                R, A, S, V, W, P,
            }

            internal enum RouterStatusProperty
            {
                // start counting from 1,
                // because there is the "r" control word
                // on the index 0.
                Nickname = 1,
                Identity,
                Digest,
                PublicationDate,
                PublicationTime,
                IPAddress,
                ORPort,
                DirectoryPort,

                // router_status_entry_r_item_count = 9
                router_status_entry_r_item_count,
            }

            [Flags()]
            internal enum RouterStatusType
            {
                None = 0x0000,
                Authority = 0x0001,
                BadExit = 0x0002,
                Exit = 0x0004,
                Fast = 0x0008,
                Guard = 0x0010,
                HiddenServiceDirectory = 0x0020,
                Named = 0x0040,
                NoEdConsensus = 0x0080,
                Stable = 0x0100,
                Running = 0x0200,
                Unnamed = 0x0400,
                Valid = 0x0800,
                V2Directory = 0x1000,
            }
        }
    }
}
