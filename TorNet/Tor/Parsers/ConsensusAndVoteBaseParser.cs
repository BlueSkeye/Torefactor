using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        }

        protected ConsensusAndVoteBaseParser(DocumentType type, ConsensusOrVote target)
        {
            if (null == target) { throw new ArgumentNullException(); }
            // Looks like the two next lines are redundant ? They're not.
            _target = target;
            SetTarget(target);
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

        internal DateTime ValidAfter
        {
            set { _target.ValidAfter = value; }
        }

        private void AssertEndOfLine(ParserState newState)
        {
            int itemsCount = _items.Length;
            if ((itemsCount + 1) != _currentItemIndex) {
                throw new ParsingException("{0}Extra arguments found at line {1}.",
                    _invalidDocumentPrefix, _currentLineNumber);
            }
            if ((int)newState < (int)_currentState) {
                ParserInternalError("State switch mismatch from {0} to {1}",
                    _currentState, newState);
            }
            _currentState = newState;
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

        private void CaptureItem()
        {
            if (_items.Length <= _currentItemIndex) {
                throw new ParsingException("{0}Incomplete line #{1}",
                    _invalidDocumentPrefix, _currentLineNumber);
            }
            _currentItemText = _items[_currentItemIndex];
            return;
        }

        private DateTime FetchTimestampItem()
        {
            CaptureItem();
            DateTime result;
            if (!DateTime.TryParseExact(_currentItemText, "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.None, out result)) {
                ParsingError("Expected an horodate. Found {0}.", _currentItemText);
            }
            return result;
        }

        private int FetchIntegerItem()
        {
            CaptureItem();
            int result;
            if (!int.TryParse(_currentItemText, out result)) {
                ParsingError("Expected and integer. Found {0}.", _currentItemText);
            }
            return result;
        }

        private ParserState NextDocumentState
        {
            get {
                switch (_documentType) {
                    case DocumentType.Consensus:
                        switch (_currentState) {
                            case ParserState.VoteStatus:
                                return ParserState.ConsensusMethod;
                            default:
                                break;
                        }
                        break;
                    default:
                        break;
                }
                WTF();
                // Unreachable
                return ParserState.Undefined;
            }
        }

        protected void _Parse(string content)
        {
            string[] lines = content.Split('\n');
            _currentState = ParserState.Start;
            bool performStandardChecks = false;

            try {
                foreach (string currentLine in lines) {
                    _currentLineNumber++;
                    if (string.IsNullOrWhiteSpace(currentLine)) {
                        ParsingError("Found empty");
                    }
                    _items = currentLine.Split(' ');
                    string keyword = _items[0];
                    _currentItemIndex = 1;

                    if (performStandardChecks) {
                        AssertExpectedKeyword(_currentState, keyword);
                        CaptureItem();
                    }

                    switch (_currentState) {
                        case ParserState.Start:
                            _currentState = ParserState.NetworkStatusVersion;
                            performStandardChecks = true;
                            break;
                        case ParserState.NetworkStatusVersion:
                            if (3 != FetchIntegerItem()) {
                                ParsingError("Version '{0}' not supported.", _currentItemText);
                            }
                            AssertEndOfLine(ParserState.VoteStatus);
                            break;
                        case ParserState.VoteStatus:
                            AssertStatus(_currentItemText);
                            AssertEndOfLine(NextDocumentState);
                            break;
                        case ParserState.ConsensusMethod:
                            SetConsensusMethod(FetchIntegerItem());
                            AssertEndOfLine(ParserState.ValidAfter);
                            break;
                        case ParserState.ValidAfter:
                            ValidAfter = FetchTimestampItem();
                            throw new NotImplementedException();
                        default:
                            throw new ParsingException("Internal error : unexpected state {0}",
                                _currentState);
                    }
                }
            }
            finally {
                if (ParserState.Done != _currentState) {
                    ParsingError("Ending with unexpected parser state {0}", _currentState);
                }
            }
        }

        protected void ParserInternalError(string message, params object[] args)
        {
            ParsingError("Internal error - " + (message ?? ""), args);
        }

        protected void ParsingError(string message, params object[] args)
        {
            throw new ParsingException(
                _invalidDocumentPrefix + " line #" + _currentLineNumber.ToString() + " : " +message, args);
        }

        /// <summary>Should we land here, there is a severe logical error.</summary>
        protected void WTF()
        {
            ParsingError("WTF");
        }

        /// <summary>This method is intended to let the subclass store the instance
        /// as a member in order to speed up access.</summary>
        /// <param name="candidate"></param>
        protected abstract void SetTarget(ConsensusOrVote candidate);

        protected abstract void SetConsensusMethod(int value);

        private int _currentItemIndex;
        private string _currentItemText;
        private int _currentLineNumber;
        private ParserState _currentState;
        private DocumentType _documentType;
        private static Dictionary<ParserState, string> _expectedKeywords;
        private string _invalidDocumentPrefix;
        private string[] _items;
        private ConsensusOrVote _target;

        protected enum DocumentType
        {
            Undefined,
            Consensus,
            Vote
        }

        /// <summary>The state value describes which element is to be handled
        /// during next loop.</summary>
        private enum ParserState
        {
            Undefined,
            Start,
            NetworkStatusVersion,
            VoteStatus,
            ConsensusMethod,
            ValidAfter,
            Done
        }
    }
}
