using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;

namespace TorNet.Tor.Parsers
{
    /// <summary></summary>
    /// <remarks>Parser internal errorexceptions with WTF messages denotes very
    /// severe internal logical errors.</remarks>
    internal abstract class ConsensusAndVoteBaseParser
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

        protected int CurrentLineNumber
        {
            get { return _currentLineNumber; }
        }

        private string DocumentName
        {
            get {
                switch (_documentType) {
                    case DocumentType.Consensus:
                        return "consensus";
                    default:
                        WTF();
                        // unreachable.
                        return null;
                }
            }
        }

        private void AssertEndOfLine(ParserState newState, bool relaxOrdering = false,
            bool optional = false)
        {
            int itemsCount = _items.Length;
            if (itemsCount != _currentItemIndex) {
                throw new ParsingException("{0}Extra arguments found at line {1}.",
                    _invalidDocumentPrefix, _currentLineNumber);
            }
            SwitchToState(newState, relaxOrdering);
            if (optional) { _performStandardChecks = false; }
            return;
        }

        private void AssertExpectedKeyword(ParserState currentState, string candidate)
        {
            string keyword;

            if (string.IsNullOrEmpty(candidate)) {
                throw new ArgumentNullException();
            }
            if (!_expectedKeywords.TryGetValue(currentState, out keyword)) {
                throw new ParsingException("Internal error : No expected keyword found for parser state {0}",
                    currentState);
            }
            if (keyword != candidate) {
                throw new ParsingException("{0}Expecting {1} keyword. Found {2].",
                    _invalidDocumentPrefix, keyword, candidate);
            }
            return;
        }

        protected abstract void AssertStatus(string candidate);

        private string CaptureItem()
        {
            if (!CaptureOptionalItem()) {
                ParsingError("Incomplete line.");
            }
            return _currentItemText;
        }

        private string CaptureLineAsSingleItem()
        {
            int totalLength = _currentLineText.Length - (_currentKeyword.Length + 1);
            try {
                return (0 == totalLength)
                    ? string.Empty
                    : _currentLineText.Substring(_currentLineText.Length - totalLength);
            }
            finally { _currentItemIndex = _items.Length; }
        }

        private bool CaptureOptionalItem()
        {
            if (_items.Length <= _currentItemIndex) {
                return false;
            }
            string candidate = _items[_currentItemIndex];
            if (string.Empty == candidate) {
                throw new ParsingException(
                    "Multiple consecutive spaces encountered.");
            }
            _currentItemText = candidate;
            _currentItemIndex++;
            return true;
        }

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
            if (ParserState.Undefined == nextState) { WTF(); }
            AssertEndOfLine(nextState, relaxOrdering, optional);
            return;
        }

        private int FetchIntegerItem()
        {
            CaptureItem();
            int result;
            if (!int.TryParse(_currentItemText, out result)) {
                ParsingError("Expected an integer. Found {0}.", _currentItemText);
            }
            return result;
        }

        private IPAddress FetchIPAddressItem()
        {
            CaptureItem();
            IPAddress result;
            if (!IPAddress.TryParse(_currentItemText, out result)) {
                ParsingError("Expected an IP address. Found {0}.", _currentItemText);
            }
            return result;
        }

        private IPEndPoint FetchIPEndPoint()
        {
            bool errorEncountered = false;
            CaptureItem();
            try {
                int splitAt;

                if (_currentItemText.StartsWith("[")) {
                    int closingBracketIndex = _currentItemText.IndexOf(']');
                    if (2 > closingBracketIndex) {
                        errorEncountered = true;
                        return null;
                    }
                    splitAt = _currentItemText.IndexOf(':', closingBracketIndex);
                }
                else { splitAt = _currentItemText.IndexOf(':'); }
                IPAddress ipAddress;
                ushort port;

                if (   (-1 != splitAt)
                    && (0 != splitAt)
                    && (_currentItemText.Length > (splitAt + 1))
                    && IPAddress.TryParse(_currentItemText.Substring(0, splitAt), out ipAddress)
                    && ushort.TryParse(_currentItemText.Substring(splitAt + 1), out port))
                {
                    return new IPEndPoint(ipAddress, port);
                }
                errorEncountered = true;
                return null;
            }
            finally {
                if (errorEncountered) {
                    ParsingError("Expecting an IP endpoint. Found '{0}'", _currentItemText);
                }
            }
        }

        private List<KeyValuePair<string, int>> FetchKeyValuePairs()
        {
            List<KeyValuePair<string, int>> result = new List<KeyValuePair<string, int>>();
            while (CaptureOptionalItem()) {
                string parameterName;
                string rawValue;
                int value = 0;
                if (!SplitPair(_currentItemText, '=', out parameterName, out rawValue)
                    || !int.TryParse(rawValue, out value))
                {
                    ParsingError("Invalid parameter '{0}'.", _currentItemText);
                    // Never reached
                }
                result.Add(new KeyValuePair<string, int>(parameterName, value));
            }
            return result;
        }

        private ushort FetchPortItem()
        {
            CaptureItem();
            ushort result;
            if (!ushort.TryParse(_currentItemText, out result)) {
                ParsingError("Expected and unsigned short. Found {0}.", _currentItemText);
            }
            return result;
        }

        private string FetchSignature(IEnumerator lineEnumerator)
        {
            StringBuilder builder = new StringBuilder();

            string currentLine;
            if (!lineEnumerator.MoveNext()) {
                ParsingError("Incomplete signature line.");
            }
            _currentLineNumber++;
            currentLine = (string)lineEnumerator.Current;
            if (SignatureHeader != currentLine) {
                ParsingError("Expected signature header. Found {0}", currentLine);
            }
            while (true) {
                if (!lineEnumerator.MoveNext()) {
                    ParsingError("Incomplete signature line.");
                }
                _currentLineNumber++;
                currentLine = (string)lineEnumerator.Current;
                if (SignatureFooter == currentLine) {
                    return builder.ToString();
                }
                builder.Append(currentLine);
            }
        }

        private DateTime FetchTimestampItem()
        {
            string candidate = CaptureItem() + " " + CaptureItem();
            DateTime result;
            if (!DateTime.TryParseExact(candidate, "yyyy-MM-dd HH:mm:ss", null, DateTimeStyles.None, out result)) {
                ParsingError("Expected an horodate. Found {0}.", _currentItemText);
            }
            return result;
        }

        private TorVersion[] FetchVersionsListItem()
        {
            CaptureItem();
            List<TorVersion> result = new List<TorVersion>();
            string[] items = _currentItemText.Split(',');
            foreach(string item in items) {
                string versionString;
                string qualifier;
                if (!SplitPair(item, '-', out versionString, out qualifier, true)) {
                    ParsingError("Invalid version number {0}.", item);
                }
                Version parsedVersion;
                if (!Version.TryParse(versionString, out parsedVersion)) {
                    ParsingError("Ill-formed version number '{0}'.", item);
                }
                result.Add(new TorVersion(parsedVersion, qualifier));
            }
            return result.ToArray();
        }

        protected void _Parse(string content)
        {
            bool exceptionTriggered = false;
            string[] lines = content.Split('\n');
            _currentState = ParserState.NetworkStatusVersion;
            _performStandardChecks = true;
            IEnumerator lineEnumerator = null;
            int subItemIndex;

            try {
                Authority currentAuthority = null;
                lineEnumerator = lines.GetEnumerator();
                while ((ParserState.Done != _currentState) && lineEnumerator.MoveNext()) {
                    _currentLineText = (string)lineEnumerator.Current;
                    _currentLineNumber++;
                    if (string.IsNullOrWhiteSpace(_currentLineText)) {
                        if (lineEnumerator.MoveNext()) {
                            ParsingError("Found empty");
                        }
                        _currentKeyword = null;
                        _items = new string[0];
                        _currentItemIndex = 1;
                    }
                    else {
                        _items = _currentLineText.Split(' ');
                        _currentKeyword = _items[0];
                        _currentItemIndex = 1;
                    }

                StateSwitched:
                    if (_performStandardChecks) {
                        AssertExpectedKeyword(_currentState, _currentKeyword);
                    }
                    else { _performStandardChecks = true; }

                    switch (_currentState) {
                        case ParserState.NetworkStatusVersion:
                            if (3 != FetchIntegerItem()) {
                                ParsingError("Version '{0}' not supported.", _currentItemText);
                            }
                            AssertEndOfLine(ParserState.VoteStatus);
                            break;
                        case ParserState.VoteStatus:
                            CaptureItem();
                            AssertStatus(_currentItemText);
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
                            if ("package" != _currentKeyword) {
                                SwitchToState(ParserState.KnownFlags);
                                goto StateSwitched;
                            }
                            throw new NotImplementedException();
                        case ParserState.KnownFlags:
                            List<string> knownFlags = new List<string>();
                            while (CaptureOptionalItem()) {
                                knownFlags.Add(_currentItemText);
                            }
                            _target.KnownFlags = knownFlags.ToArray();
                            DoConditionalSwitchAtEndOfLine();
                            break;
                        case ParserState.Params:
                            if ("params" != _currentKeyword) {
                                SwitchToState(ParserState.DirSource);
                                goto StateSwitched;
                            }
                            _target.Parameters = FetchKeyValuePairs().ToArray();
                            AssertEndOfLine(ParserState.DirSource, false, false);
                            break;
                        case ParserState.DirSource:
                            if ("dir-source" != _currentKeyword) {
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
                            if ("r" != _currentKeyword) {
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
                            if ("a" != _currentKeyword) {
                                SwitchToState(ParserState.S);
                                goto StateSwitched;
                            }
                            _currentRouter.IPV6EndPoint = FetchIPEndPoint();
                            AssertEndOfLine(ParserState.A, false, true);
                            break;
                        case ParserState.S:
                            if ("s" != _currentKeyword) {
                                ParsingError("Expecting S entry. Found '{0}'.", _currentKeyword);
                            }
                            List<string> routerFlags = new List<string>();
                            while (CaptureOptionalItem()) {
                                routerFlags.Add(_currentItemText);
                            }
                            _currentRouter.Flags = ParseRouterFlags(routerFlags);
                            AssertEndOfLine(ParserState.V, false, true);
                            break;
                        case ParserState.V:
                            if ("v" != _currentKeyword) {
                                SwitchToState(ParserState.W);
                                goto StateSwitched;
                            }
                            _currentRouter.Version = CaptureLineAsSingleItem();
                            AssertEndOfLine(ParserState.W);
                            break;
                        case ParserState.W:
                            if ("w" != _currentKeyword) {
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
                            if ("p" != _currentKeyword) {
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
                                    ParsingError("Unexpected acept/reject directive : '{0}'.", _currentItemText);
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
                            if ("bandwidth-weights" != _currentKeyword) {
                                SwitchToState(ParserState.DirectorySignature);
                                goto StateSwitched;
                            }
                            //TODO : Dont handle this for now.
                            SkipLineAndSwitch(ParserState.DirectorySignature);
                            break;
                        case ParserState.DirectorySignature:
                            if ("directory-signature" != _currentKeyword) {
                                if (!_firstSignatureFound) {
                                    ParsingError("Document not signed.");
                                }
                                SwitchToState(ParserState.Done);
                                break;
                            }
                            if (_firstSignatureFound && (DocumentType.Consensus != _documentType)) {
                                ParsingError("More than one signature is not expected.");
                            }
                            //TODO : Dont handle this for now.
                            while (CaptureOptionalItem()) { }
                            FetchSignature(lineEnumerator);
                            AssertEndOfLine(ParserState.DirectorySignature, false, true);
                            _firstSignatureFound = true;
                            break;
                        default:
                            throw new ParsingException("Internal error : unexpected state {0}",
                                _currentState);
                    }
                }
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
                    if ((null != lineEnumerator) && lineEnumerator.MoveNext()) {
                        ParsingError("End state reached with remaining lines.");
                    }
                }
                if (null != _currentRouter) { WTF(); }
            }
        }

        protected void ParsingError(string message, params object[] args)
        {
            throw new ParsingException(
                _invalidDocumentPrefix + " line #" + _currentLineNumber.ToString() + " : " + message, args);
        }

        protected void ParserInternalError(string message, params object[] args)
        {
            ParsingError("Internal error - " + (message ?? ""), args);
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
            if (!_expectedKeywords.ContainsKey(switchTo)) { WTF(); }
            if (null != _expectedKeywords[switchTo]) { WTF(); }
#endif
            SkipLineAndSwitch(switchTo, relaxOrdering);
            _performStandardChecks = false;
            return;
        }

        private bool SplitPair(string item, char splitter, out string key,
            out string value, bool optional = false)
        {
            key = null;
            value = null;
            int splitIndex = item.IndexOf(splitter);
            if ((0 == splitIndex) || (splitIndex == item.Length - 1)) {
                return false;
            }
            if (!optional && (-1 == splitIndex)) { return false; }
            key = (-1 == splitIndex)
                ? item
                : item.Substring(0, splitIndex);
            value = (-1 == splitIndex)
                ? string.Empty
                : item.Substring(splitIndex + 1);
            return true;
        }

        private void SwitchToState(ParserState newState, bool relaxOrdering = false)
        {
            if (!relaxOrdering && ((int)newState < (int)_currentState)) {
                ParserInternalError("State switch mismatch from {0} to {1}",
                    _currentState, newState);
            }
            _currentState = newState;
            _performStandardChecks = true;
            return;
        }

        /// <summary>Should we land here, there is a severe logical error.</summary>
        protected void WTF()
        {
            ParsingError("WTF");
        }

        private const string SignatureHeader = "-----BEGIN SIGNATURE-----";
        private const string SignatureFooter = "-----END SIGNATURE-----";
        private int _currentItemIndex;
        private string _currentItemText;
        private string _currentLineText;
        private string _currentKeyword;
        private int _currentLineNumber;
        private OnionRouter _currentRouter;
        private ParserState _currentState;
        private DocumentType _documentType;
        private static Dictionary<ParserState, string> _expectedKeywords;
        private bool _firstSignatureFound = false;
        private string _invalidDocumentPrefix;
        private string[] _items;
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
        private enum ParserState
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
