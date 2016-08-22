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
            /// <param name="rejectOutdated">true if the consensus must be rejected
            /// ifvalidty date exceeds current date. Notwithstanding this flag, any
            /// other malformation will trigger an exception.</param>
            internal static Consensus ParseAndValidate(string content, bool rejectOutdated = true,
                SignatureDescriptor.ValidationPolicy validationPolicy = SignatureDescriptor.ValidationPolicy.AllSignaturesMustMatch)
            {
                if (SignatureDescriptor.ValidationPolicy.Undefined == validationPolicy) {
                    throw new ArgumentException();
                }
                bool noMatchEncountered = true;
                List<Authority> validSigner = new List<Authority>();
                Consensus target = new Consensus();
                Parser parser = new Parser(target);
                parser._Parse(content, rejectOutdated);
                foreach(SignatureDescriptor descriptor in target.EnumerateSignatureDescriptors()) {
                    bool thisSignatureIsValid = descriptor.Validate(validationPolicy);

                    switch (validationPolicy) {
                        case SignatureDescriptor.ValidationPolicy.AllSignaturesMustMatch:
                            if (!thisSignatureIsValid) {
                                // Note : this check is already implemented in the validator.
                                throw new TorSecurityException();
                            }
                            break;
                        case SignatureDescriptor.ValidationPolicy.DontCare:
                            break;
                        case SignatureDescriptor.ValidationPolicy.AtLeastOneSignatureMustMatch:
                            if (thisSignatureIsValid) {
                                noMatchEncountered = false;
                            }
                            break;
                        case SignatureDescriptor.ValidationPolicy.AtLeastOneSignaturePerSignerMustMatch:
                            if (thisSignatureIsValid) {
                                Authority signer = descriptor.Signer;
                                if (!validSigner.Contains(signer)) {
                                    validSigner.Add(signer);
                                }
                            }
                            break;
                        default:
                            Helpers.WTF();
                            break;
                    }
                    if (   (SignatureDescriptor.ValidationPolicy.AtLeastOneSignatureMustMatch == validationPolicy)
                        && noMatchEncountered)
                    {
                        throw new TorSecurityException();
                    }
                }
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

            protected override void SetTarget(ConsensusOrVote candidate)
            {
                Consensus consensus = candidate as Consensus;
                if (null != _target) { Helpers.WTF(); }
                if (null == consensus) { Helpers.WTF(); }
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
