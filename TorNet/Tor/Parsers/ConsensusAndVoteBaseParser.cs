using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

using TorNet.Cryptography;

namespace TorNet.Tor.Parsers
{
    /// <summary></summary>
    /// <remarks>Parser internal errorexceptions with WTF messages denotes very
    /// severe internal logical errors.</remarks>
    internal abstract class ConsensusAndVoteBaseParser : BaseParser<ConsensusAndVoteBaseParser.ParserState>
    {
        static ConsensusAndVoteBaseParser()
        {
            _expectedKeywords = new Dictionary<ParserState, string>();
            _expectedKeywords.Add(ParserState.NetworkStatusVersion, "network-status-version");
            _expectedKeywords.Add(ParserState.VoteStatus, "vote-status");
            _expectedKeywords.Add(ParserState.ConsensusMethod, "consensus-method");
            _expectedKeywords.Add(ParserState.ValidAfter, "valid-after");
            _expectedKeywords.Add(ParserState.FreshUntil, "fresh-until");
            _expectedKeywords.Add(ParserState.ValidUntil, "valid-until");
            _expectedKeywords.Add(ParserState.VotingDelay, "voting-delay");
            _expectedKeywords.Add(ParserState.ClientVersions, "client-versions");
            _expectedKeywords.Add(ParserState.ServerVersions, "server-versions");
            _expectedKeywords.Add(ParserState.Package, "package");
            _expectedKeywords.Add(ParserState.KnownFlags, "known-flags");
            _expectedKeywords.Add(ParserState.Params, "params");
            _expectedKeywords.Add(ParserState.DirSource, "dir-source");
            _expectedKeywords.Add(ParserState.Contact, "contact");
            _expectedKeywords.Add(ParserState.VoteDigest, "vote-digest");
            _expectedKeywords.Add(ParserState.R, "r");
            _expectedKeywords.Add(ParserState.A, "a");
            _expectedKeywords.Add(ParserState.S, "s");
            _expectedKeywords.Add(ParserState.V, "v");
            _expectedKeywords.Add(ParserState.W, "w");
            _expectedKeywords.Add(ParserState.P, "p");
            _expectedKeywords.Add(ParserState.DirectoryFooter, "directory-footer");
            _expectedKeywords.Add(ParserState.BandwidthWeights, "bandwidth-weights");
            _expectedKeywords.Add(ParserState.DirectorySignature, "directory-signature");
        }

        protected override string InvalidDocumentPrefix
        {
            get { return _invalidDocumentPrefix; }
        }

        protected override Dictionary<ParserState, string> StateExpectations
        {
            get { return _expectedKeywords; }
        }

        protected ConsensusAndVoteBaseParser(DocumentType type, ConsensusOrVote target)
        {
            if (null == target) { throw new ArgumentNullException(); }
            // Looks like the two next lines are redundant ? They're not.
            _target = target;
            SetTarget(target);
            _documentType = type;
            _invalidDocumentPrefix = "Invalid " + DocumentName + " document ";
            switch(type) {
                case DocumentType.Consensus:
                    break;
                default:
                    ParserInternalError("Unsupported document type {0}", type);
                    // Not reachable.
                    return;
            }
        }

        private string DocumentName
        {
            get {
                switch (_documentType) {
                    case DocumentType.Consensus:
                        return "consensus";
                    default:
                        Helpers.WTF();
                        // unreachable.
                        return null;
                }
            }
        }

        protected abstract void AssertStatus(string candidate);

        private void DoConditionalSwitchAtEndOfLine()
        {
            ParserState nextState = ParserState.Undefined;
            bool optional = false;
            bool relaxOrdering = false;
            switch (_documentType) {
                case DocumentType.Consensus:
                    switch (_currentState) {
                        case ParserState.VoteStatus:
                            nextState = ParserState.ConsensusMethod;
                            break;
                        case ParserState.ValidAfter:
                            nextState = ParserState.FreshUntil;
                            break;
                        case ParserState.KnownFlags:
                            // Unclear whether shared-rand-... entries can be
                            // found in consensus documents.
                            nextState = ParserState.Params;
                            optional = true;
                            break;
                        case ParserState.P:
                            nextState = ParserState.R;
                            optional = true;
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
            if (ParserState.Undefined == nextState) { Helpers.WTF(); }
            AssertEndOfLine(nextState, relaxOrdering, optional);
            return;
        }

        protected bool _Parse(string content, bool rejectOutdated)
        {
            bool exceptionTriggered = false;
            bool outdatedEncountered = false;
            int subItemIndex;

            _currentState = ParserState.NetworkStatusVersion;
            _performStandardChecks = true;
            base.SetContent(content, _expectedKeywords[ParserState.DirectorySignature]);
            try {
                Authority currentAuthority = null;
                while ((ParserState.Done != _currentState) && base.AcquireNextLine()) {
                StateSwitched:
                    if (_performStandardChecks) {
                        AssertExpectedKeyword(_currentState, CurrentKeyword);
                    }
                    else { _performStandardChecks = true; }

                    switch (_currentState) {
                        case ParserState.NetworkStatusVersion:
                            if (3 != FetchIntegerItem()) {
                                ParsingError("Version '{0}' not supported.", CurrentItemText);
                            }
                            AssertEndOfLine(ParserState.VoteStatus);
                            break;
                        case ParserState.VoteStatus:
                            CaptureItem();
                            AssertStatus(CurrentItemText);
                            DoConditionalSwitchAtEndOfLine();
                            break;
                        case ParserState.ConsensusMethod:
                            SetConsensusMethod((VotingMethod)FetchIntegerItem());
                            AssertEndOfLine(ParserState.ValidAfter);
                            break;
                        case ParserState.ValidAfter:
                            _target.ValidAfterUTC = FetchTimestampItem();
                            DoConditionalSwitchAtEndOfLine();
                            break;
                        case ParserState.FreshUntil:
                            _target.FreshUntilUTC = FetchTimestampItem();
                            AssertEndOfLine(ParserState.ValidUntil);
                            break;
                        case ParserState.ValidUntil:
                            _target.ValidUntilUTC = FetchTimestampItem();
                            AssertEndOfLine(ParserState.VotingDelay);
                            if (rejectOutdated && (DateTime.UtcNow > _target.ValidUntilUTC)) {
                                outdatedEncountered = true;
                                return false;
                            }
                            break;
                        case ParserState.VotingDelay:
                            _target.VoteSeconds = FetchIntegerItem();
                            _target.DistSeconds = FetchIntegerItem();
                            AssertEndOfLine(ParserState.ClientVersions);
                            break;
                        case ParserState.ClientVersions:
                            _target.ClientVersions = FetchVersionsListItem();
                            AssertEndOfLine(ParserState.ServerVersions);
                            break;
                        case ParserState.ServerVersions:
                            _target.ServerVersions = FetchVersionsListItem();
                            AssertEndOfLine(ParserState.Package,false, true);
                            break;
                        case ParserState.Package:
                            if (_expectedKeywords[ParserState.Package] != CurrentKeyword) {
                                SwitchToState(ParserState.KnownFlags);
                                goto StateSwitched;
                            }
                            throw new NotImplementedException();
                        case ParserState.KnownFlags:
                            List<string> knownFlags = new List<string>();
                            while (CaptureOptionalItem()) {
                                knownFlags.Add(CurrentItemText);
                            }
                            _target.KnownFlags = knownFlags.ToArray();
                            DoConditionalSwitchAtEndOfLine();
                            break;
                        case ParserState.Params:
                            if ("params" != CurrentKeyword) {
                                SwitchToState(ParserState.DirSource);
                                goto StateSwitched;
                            }
                            _target.Parameters = FetchKeyValuePairs().ToArray();
                            AssertEndOfLine(ParserState.DirSource, false, false);
                            break;
                        case ParserState.DirSource:
                            if ("dir-source" != CurrentKeyword) {
                                SwitchToState(ParserState.R);
                                goto StateSwitched;
                            }
                            currentAuthority = new Authority(CaptureItem(), CaptureItem(),
                                CaptureItem(), FetchIPAddressItem(), FetchPortItem(), FetchPortItem());
                            AssertEndOfLine(ParserState.Contact);
                            break;
                        case ParserState.Contact:
                            currentAuthority.Contact = CaptureLineAsSingleItem();
                            AssertEndOfLine(ParserState.VoteDigest);
                            _target.AddAuthority(currentAuthority);
                            break;
                        case ParserState.VoteDigest:
                            _target.SetVoteDigest(currentAuthority, CaptureItem());
                            currentAuthority = null;
                            // Loop back on next source.
                            AssertEndOfLine(ParserState.DirSource, true, true);
                            break;
                        case ParserState.R:
                            if ("r" != CurrentKeyword) {
                                SwitchToState(ParserState.DirectoryFooter);
                                goto StateSwitched;
                            }
                            _currentRouter = new OnionRouter(_target, CaptureItem(), CaptureItem(),
                                CaptureItem(), FetchTimestampItem(), FetchIPAddressItem(),
                                FetchPortItem(), FetchPortItem());
                            _target.Register(_currentRouter);
                            AssertEndOfLine(ParserState.A, false, true);
                            break;
                        case ParserState.A:
                            if ("a" != CurrentKeyword) {
                                SwitchToState(ParserState.S);
                                goto StateSwitched;
                            }
                            _currentRouter.IPV6EndPoint = FetchIPEndPoint();
                            AssertEndOfLine(ParserState.A, false, true);
                            break;
                        case ParserState.S:
                            if ("s" != CurrentKeyword) {
                                ParsingError("Expecting S entry. Found '{0}'.", CurrentKeyword);
                            }
                            List<string> routerFlags = new List<string>();
                            while (CaptureOptionalItem()) {
                                routerFlags.Add(CurrentItemText);
                            }
                            _currentRouter.Flags = ParseRouterFlags(routerFlags);
                            AssertEndOfLine(ParserState.V, false, true);
                            break;
                        case ParserState.V:
                            if ("v" != CurrentKeyword) {
                                SwitchToState(ParserState.W);
                                goto StateSwitched;
                            }
                            _currentRouter.Version = CaptureLineAsSingleItem();
                            AssertEndOfLine(ParserState.W);
                            break;
                        case ParserState.W:
                            if ("w" != CurrentKeyword) {
                                SwitchToState(ParserState.P);
                                goto StateSwitched;
                            }
                            bool errorEncountered = false;
                            List<KeyValuePair<string, int>> bandwidthItems = FetchKeyValuePairs();
                            if ((1 <= bandwidthItems.Count) && ("Bandwidth" == bandwidthItems[0].Key)) {
                                _currentRouter.EstimatedBandwidth = bandwidthItems[0].Value;
                                subItemIndex = 1;
                                if (subItemIndex < bandwidthItems.Count) {
                                    if ("Measured" == bandwidthItems[subItemIndex].Key) {
                                        _currentRouter.MeasuredBandwidth = bandwidthItems[subItemIndex++].Value;
                                    }
                                    if (subItemIndex < bandwidthItems.Count) {
                                        if (("Unmeasured" == bandwidthItems[subItemIndex].Key)
                                            && (1 == bandwidthItems[subItemIndex].Value))
                                        {
                                            _currentRouter.Unmeasured = true;
                                            subItemIndex++;
                                        }
                                    }
                                    if (subItemIndex < bandwidthItems.Count) {
                                        errorEncountered = true;
                                    }
                                }
                            }
                            if (errorEncountered) {
                                ParsingError("Ill-formed relay bandwidth description.");
                            }
                            AssertEndOfLine(ParserState.P);
                            break;
                        case ParserState.P:
                            if ("p" != CurrentKeyword) {
                                // TODO : Consider a conditional switch when handling both votes
                                // and consensus.
                                SwitchToState(ParserState.R, true);
                                goto StateSwitched;
                            }
                            bool accepting = false;

                            switch (CaptureItem()) {
                                case "accept":
                                    accepting = true;
                                    break;
                                case "reject":
                                    accepting = false;
                                    break;
                                default:
                                    ParsingError("Unexpected acept/reject directive : '{0}'.", CurrentItemText);
                                    break;
                            }
                            string[] listItems = CaptureItem().Split(',');
                            foreach(string candidate in listItems) {
                                string fromText;
                                string toText;
                                if (!SplitPair(candidate, '-', out fromText, out toText, true)) {
                                    ParsingError("Invalid address range {0}.", candidate);
                                }
                                if (string.Empty == toText) { toText = fromText; }
                                ushort from = 0;
                                ushort to = 0;
                                if (!ushort.TryParse(fromText, out from) || !ushort.TryParse(toText, out to)) {
                                    ParsingError("Invalid address range {0}.", candidate);
                                }
                                if (accepting) {
                                    _currentRouter.Accept(from, to);
                                }
                                else {
                                    _currentRouter.Reject(from, to);
                                }
                            }
                            _currentRouter = null;
                            AssertEndOfLine(ParserState.R, true, true);
                            break;
                        case ParserState.DirectoryFooter:
                            AssertEndOfLine(ParserState.BandwidthWeights, false, true);
                            break;
                        case ParserState.BandwidthWeights:
                            if ("bandwidth-weights" != CurrentKeyword) {
                                SwitchToState(ParserState.DirectorySignature);
                                goto StateSwitched;
                            }
                            //TODO : Dont handle this for now.
                            SkipLineAndSwitch(ParserState.DirectorySignature);
                            break;
                        case ParserState.DirectorySignature:
                            if ("directory-signature" != CurrentKeyword) {
                                if (!_firstSignatureFound) {
                                    ParsingError("Document not signed.");
                                }
                                SwitchToState(ParserState.Done);
                                break;
                            }
                            if (_firstSignatureFound && (DocumentType.Consensus != _documentType)) {
                                ParsingError("More than one signature is not expected.");
                            }
                            // TODO : This must be extracted from this method and performed during
                            // a later step.
                            if (PrepareSignatureVerification()) {
                                _firstSignatureFound = true;
                            }
                            AssertEndOfLine(ParserState.DirectorySignature, false, true);
                            break;
                        default:
                            throw new ParsingException("Internal error : unexpected state {0}",
                                _currentState);
                    }
                }
                return true;
            }
            catch (Exception e) {
                if (!(e is ParsingException)) {
                    throw new ParsingException(e);
                }
                exceptionTriggered = true;
                throw;
            }
            finally {
                if (!exceptionTriggered) {
                    if (ParserState.Done != _currentState) {
                        ParsingError("Ending with unexpected parser state {0}", _currentState);
                    }
                    if (base.AcquireNextLine()) {
                        ParsingError("End state reached with remaining lines.");
                    }
                }
                if (!outdatedEncountered && (null != _currentRouter)) { Helpers.WTF(); }
            }
        }

        private OnionRouter.StatusFlags ParseRouterFlags(ICollection<string> flagNames)
        {
            OnionRouter.StatusFlags result = 0;
            foreach(string candidate in flagNames) {
                switch(candidate) {
                    case "Authority":
                        result |= OnionRouter.StatusFlags.Authority;
                        break;
                    case "BadExit":
                        result |= OnionRouter.StatusFlags.BadExit;
                        break;
                    case "Exit":
                        result |= OnionRouter.StatusFlags.Exit;
                        break;
                    case "Fast":
                        result |= OnionRouter.StatusFlags.Fast;
                        break;
                    case "Guard":
                        result |= OnionRouter.StatusFlags.Guard;
                        break;
                    case "HSDir":
                        result |= OnionRouter.StatusFlags.HSDir;
                        break;
                    case "Named":
                        result |= OnionRouter.StatusFlags.Named;
                        break;
                    case "NoEdConsensus":
                        result |= OnionRouter.StatusFlags.NoEd25519Consensus;
                        break;
                    case "Stable":
                        result |= OnionRouter.StatusFlags.Stable;
                        break;
                    case "Running":
                        result |= OnionRouter.StatusFlags.Running;
                        break;
                    case "Unnamed":
                        result |= OnionRouter.StatusFlags.Unnamed;
                        break;
                    case "Valid":
                        result |= OnionRouter.StatusFlags.Valid;
                        break;
                    case "V2Dir":
                        result |= OnionRouter.StatusFlags.V2Dir;
                        break;
                    default:
                        break;
                }
            }
            return result;
        }

        /// <summary>Retrieve last part of the consensus or vote, that is extract signatures
        /// and store then in the currently built target. There is no actual verification of
        /// the signature at this step. This is because we may not already know the signing
        /// key.</summary>
        private bool PrepareSignatureVerification()
        {
            bool result = true;
            string hashAlgorithm = CaptureItem();
            string identity = CaptureItem();
            string signingKeyDigest;

            if (!CaptureOptionalItem()) {
                signingKeyDigest = identity;
                identity = hashAlgorithm;
                hashAlgorithm = null;
            }
            else { signingKeyDigest = CurrentItemText; }
            switch (hashAlgorithm) {
                case "sha1":
                case "sha256":
                    break;
                case null:
                    hashAlgorithm = "sha1";
                    break;
                default:
                    result = false;
                    break;
            }
            if (CaptureOptionalItem()) {
                ParsingError("Directory signature entry contains extra parameters.");
            }
            byte[] signature = FetchSignature();
            Authority signer = _target.GetAuthority(identity);

            if (null == signer) {
                ParsingError("Found directory signature from unknown authority with identity '{0}'",
                    identity);
            }
            byte[] hashValue;
            switch (hashAlgorithm) {
                case "sha1":
                    hashValue = SHA1.Hash(base._toBeHashed);
                    break;
                case "sha256":
                    throw new NotImplementedException();
                default:
                    Helpers.WTF();
                    return false; // Unreachable.
            }
            _target.AddSignatureDescriptor(
                new ConsensusOrVote.SignatureDescriptor(signer, hashValue, signature));
            return result;
        }

        protected abstract void SetConsensusMethod(VotingMethod value);

        /// <summary>This method is intended to let the subclass store the instance
        /// as a member in order to speed up access.</summary>
        /// <param name="candidate"></param>
        protected abstract void SetTarget(ConsensusOrVote candidate);

        private void SkipLineAndSwitch(ParserState switchTo, bool relaxOrdering = false,
            bool optional = false)
        {
#if DEBUG
            while (CaptureOptionalItem()) ;
            AssertEndOfLine(switchTo, relaxOrdering, optional);
#else
            WTF();
#endif
        }

        private void SkipLineAndSwitchToOptional(ParserState switchTo, bool relaxOrdering = false)
        {
#if DEBUG
            if (!_expectedKeywords.ContainsKey(switchTo)) { Helpers.WTF(); }
            if (null != _expectedKeywords[switchTo]) { Helpers.WTF(); }
#endif
            SkipLineAndSwitch(switchTo, relaxOrdering);
            _performStandardChecks = false;
            return;
        }

        private OnionRouter _currentRouter;
        private ParserState _currentState;
        private DocumentType _documentType;
        private static Dictionary<ParserState, string> _expectedKeywords;
        private bool _firstSignatureFound = false;
        private string _invalidDocumentPrefix;
        private bool _performStandardChecks = false;
        private ConsensusOrVote _target;

        protected enum DocumentType
        {
            Undefined,
            Consensus,
            Vote
        }

        /// <summary>The state value describes which element is to be handled
        /// during next loop. WARNING : Do not reorder. There is a check on some
        /// variables of this type for monotonic increasing value.</summary>
        internal enum ParserState
        {
            Undefined,
            NetworkStatusVersion,
            VoteStatus,
            ConsensusMethod,
            ValidAfter,
            FreshUntil,
            ValidUntil,
            VotingDelay,
            ClientVersions,
            ServerVersions,
            Package,
            KnownFlags,
            Params,
            DirSource,
            Contact,
            VoteDigest,
            R,
            A,
            S,
            V,
            W,
            P,
            DirectoryFooter,
            BandwidthWeights,
            DirectorySignature,
            Done
        }

        internal enum VotingMethod
        {
            Basic = 1,
            UnnamedFlagAdded,
            LegacyIDKeyAdded,
            NotRunningRoutersRemoved,
            WAndPAdded,
            MeasuredBandwidthFavored,
            KeywordIntegerPairParametersAdded,
            MicrodescriptorSummariesAdded,
            FlaggedRoutersWeightsAdded,
            EdgeBugFixed,
            BadExitRemovedFromBandwidthComputation,
            AuthoritiesThresholdAddedForParameters,
            OmitRoutersWithMissingMicrodescriptors,
            ALineAdded,
            P6LineAdded,
            NTorKeysAddedToMicrodescriptors,
            UnmeasuredFlagsAdded,
            MicrodescriptorsIdAdded,
            PackagesAddedToConsensus,
            GuardFractionInformationAdded,
            Ed25519KeyAdded,
            Ed25519VotingAlgorithmInstanciationBugFix
        }
    }
}
