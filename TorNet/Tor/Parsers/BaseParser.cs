using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;
using System.Threading.Tasks;

using TorNet.Cryptography;

namespace TorNet.Tor.Parsers
{
    internal abstract class BaseParser<PS>
        where PS : IComparable
    {
        protected int CurrentItemIndex { get; private set; }
        protected string CurrentItemText { get; private set; }
        protected string CurrentKeyword { get; private set; }
        protected int CurrentLineNumber { get; private set; }

        protected abstract string InvalidDocumentPrefix { get; }
        protected abstract Dictionary<PS, string> StateExpectations { get; }

        protected bool AcquireNextLine()
        {
            if (!_lineEnumerator.MoveNext()) { return false; }
            _currentLineText = (string)_lineEnumerator.Current;
            CurrentLineNumber++;
            if (string.IsNullOrWhiteSpace(_currentLineText)) {
                //if (lineEnumerator.MoveNext()) {
                //    ParsingError("Found empty");
                //}
                CurrentKeyword = null;
                _items = new string[0];
                CurrentItemIndex = 1;
            }
            else {
                _items = _currentLineText.Split(' ');
                CurrentKeyword = _items[0];
                CurrentItemIndex = 1;
            }
            return true;
        }

        protected void AssertEndOfLine()
        {
            int itemsCount = _items.Length;
            if (itemsCount != CurrentItemIndex) {
                throw new ParsingException("{0}Extra arguments found at line {1}.",
                    InvalidDocumentPrefix, CurrentLineNumber);
            }
            return;
        }

        protected void AssertEndOfLine(PS newState, bool relaxOrdering = false,
            bool optional = false)
        {
            this.AssertEndOfLine();
            SwitchToState(newState, relaxOrdering);
            if (optional) { _performStandardChecks = false; }
            return;
        }

        protected void AssertExpectedKeyword(PS currentState, string candidate)
        {
            string keyword;

            if (string.IsNullOrEmpty(candidate)) {
                throw new ArgumentNullException();
            }
            if (!StateExpectations.TryGetValue(currentState, out keyword)) {
                throw new ParsingException("Internal error : No expected keyword found for parser state {0}",
                    currentState);
            }
            if (keyword != candidate) {
                throw new ParsingException("{0}Expecting {1} keyword. Found {2].",
                    InvalidDocumentPrefix, keyword, candidate);
            }
            return;
        }

        private void AssertInitialized()
        {
            if (null == _lineEnumerator) {
                throw new InvalidOperationException();
            }
        }

        protected string CaptureItem()
        {
            if (!CaptureOptionalItem()) {
                ParsingError("Incomplete line.");
            }
            return CurrentItemText;
        }

        protected string CaptureLineAsSingleItem()
        {
            AssertInitialized();
            int totalLength = _currentLineText.Length - (CurrentKeyword.Length + 1);
            try {
                return (0 == totalLength)
                    ? string.Empty
                    : _currentLineText.Substring(_currentLineText.Length - totalLength);
            }
            finally { CurrentItemIndex = _items.Length; }
        }

        protected bool CaptureOptionalItem()
        {
            AssertInitialized();
            if (_items.Length <= CurrentItemIndex) {
                return false;
            }
            string candidate = _items[CurrentItemIndex];
            if (string.Empty == candidate) {
                throw new ParsingException(
                    "Multiple consecutive spaces encountered.");
            }
            CurrentItemText = candidate;
            CurrentItemIndex++;
            return true;
        }

        protected byte[] FetchHexadecimalEncodedString()
        {
            CaptureItem();
            bool errorEncountered = false;
            if (0 == (CurrentItemText.Length % 2)) {
                int bytesCount = CurrentItemText.Length / 2;
                byte[] result = new byte[bytesCount];
                for(int index = 0; index < bytesCount; index++) {
                    byte extractedByte;
                    if (!byte.TryParse(CurrentItemText.Substring(2 * index, 2), out extractedByte)) {
                        errorEncountered = true;
                        break;
                    }
                    result[index] = extractedByte;
                }
                if (!errorEncountered) { return result; }
            }
            ParsingError("Expected an hexadecimal string. Found {0}.", CurrentItemText);
            // Not reachable.
            return null;
        }

        protected int FetchIntegerItem()
        {
            CaptureItem();
            int result;
            if (!int.TryParse(CurrentItemText, out result)) {
                ParsingError("Expected an integer. Found {0}.", CurrentItemText);
            }
            return result;
        }

        protected IPAddress FetchIPAddressItem()
        {
            CaptureItem();
            IPAddress result;
            if (!IPAddress.TryParse(CurrentItemText, out result)) {
                ParsingError("Expected an IP address. Found {0}.", CurrentItemText);
            }
            return result;
        }

        protected IPEndPoint FetchIPEndPoint()
        {
            bool errorEncountered = false;
            CaptureItem();
            try {
                int splitAt;

                if (CurrentItemText.StartsWith("[")) {
                    int closingBracketIndex = CurrentItemText.IndexOf(']');
                    if (2 > closingBracketIndex) {
                        errorEncountered = true;
                        return null;
                    }
                    splitAt = CurrentItemText.IndexOf(':', closingBracketIndex);
                }
                else { splitAt = CurrentItemText.IndexOf(':'); }
                IPAddress ipAddress;
                ushort port;

                if (   (-1 != splitAt)
                    && (0 != splitAt)
                    && (CurrentItemText.Length > (splitAt + 1))
                    && IPAddress.TryParse(CurrentItemText.Substring(0, splitAt), out ipAddress)
                    && ushort.TryParse(CurrentItemText.Substring(splitAt + 1), out port))
                {
                    return new IPEndPoint(ipAddress, port);
                }
                errorEncountered = true;
                return null;
            }
            finally {
                if (errorEncountered) {
                    ParsingError("Expecting an IP endpoint. Found '{0}'", CurrentItemText);
                }
            }
        }

        protected List<KeyValuePair<string, int>> FetchKeyValuePairs()
        {
            List<KeyValuePair<string, int>> result = new List<KeyValuePair<string, int>>();
            while (CaptureOptionalItem()) {
                string parameterName;
                string rawValue;
                int value = 0;
                if (!SplitPair(CurrentItemText, '=', out parameterName, out rawValue)
                    || !int.TryParse(rawValue, out value))
                {
                    ParsingError("Invalid parameter '{0}'.", CurrentItemText);
                    // Never reached
                }
                result.Add(new KeyValuePair<string, int>(parameterName, value));
            }
            return result;
        }

        protected ushort FetchPortItem()
        {
            CaptureItem();
            ushort result;
            if (!ushort.TryParse(CurrentItemText, out result)) {
                ParsingError("Expected and unsigned short. Found {0}.", CurrentItemText);
            }
            return result;
        }

        protected byte[] FetchRsaPublicKey()
        {
            AssertInitialized();
            StringBuilder builder = new StringBuilder();
            string currentLine;
            if (!_lineEnumerator.MoveNext()) {
                ParsingError("Incomplete public key line.");
            }
            CurrentLineNumber++;
            currentLine = (string)_lineEnumerator.Current;
            if (RsaPublicKeyHeader != currentLine) {
                ParsingError("Expected public key header. Found {0}", currentLine);
            }
            while (true) {
                if (!_lineEnumerator.MoveNext()) {
                    ParsingError("Incomplete public key line.");
                }
                CurrentLineNumber++;
                currentLine = (string)_lineEnumerator.Current;
                if (RsaPublicKeyFooter == currentLine) {
                    return Base64.Decode(builder.ToString());
                }
                builder.Append(currentLine);
            }
        }

        protected byte[] FetchSignature(bool allowAlternateMarkers = false)
        {
            AssertInitialized();
            StringBuilder builder = new StringBuilder();
            string currentLine;
            if (!_lineEnumerator.MoveNext()) {
                ParsingError("Incomplete signature line.");
            }
            CurrentLineNumber++;
            currentLine = (string)_lineEnumerator.Current;
            bool alternateHeader = false;
            if (SignatureHeader != currentLine) {
                if (allowAlternateMarkers
                    && (SignatureAlternateHeader == currentLine))
                {
                    alternateHeader = true;
                }
                else {
                    ParsingError("Expected signature header. Found {0}", currentLine);
                }
            }
            while (true) {
                if (!_lineEnumerator.MoveNext()) {
                    ParsingError("Incomplete signature line.");
                }
                CurrentLineNumber++;
                currentLine = (string)_lineEnumerator.Current;
                if (   (alternateHeader && (SignatureAlternateFooter == currentLine))
                    || (!alternateHeader && (SignatureFooter == currentLine)))
                {
                    return Base64.Decode(builder.ToString());
                }
                builder.Append(currentLine);
            }
        }

        protected DateTime FetchTimestampItem()
        {
            string candidate = CaptureItem() + " " + CaptureItem();
            DateTime result;
            if (!DateTime.TryParseExact(candidate, "yyyy-MM-dd HH:mm:ss", null, DateTimeStyles.None, out result)) {
                ParsingError("Expected an horodate. Found {0}.", CurrentItemText);
            }
            return result;
        }

        protected TorVersion[] FetchVersionsListItem()
        {
            CaptureItem();
            List<TorVersion> result = new List<TorVersion>();
            string[] items = CurrentItemText.Split(',');
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

        /// <summary>Grab content to be hashed for signature verification later.</summary>
        /// <param name="content"></param>
        /// <param name="endOfSignedContentKeyword"></param>
        /// <returns></returns>
        private byte[] GetToBeHashedValue(string content, string endOfSignedContentKeyword)
        {
            int endOfSignedContentIndex = content.IndexOf(endOfSignedContentKeyword);

            if (-1 == endOfSignedContentIndex) {
                ParsingError("Unable to find end of signed content.");
            }
            endOfSignedContentIndex += endOfSignedContentKeyword.Length;
            // NOTICE : We use a loose algorithm where we just seek for the line termination
            // character. The parser is expected to check the syntax. This should work as
            // long as this same tag is NOT encountered in any content.
            // TODO : Weak assumptions here. Must rework extraction.
            while (content.Length > endOfSignedContentIndex) {
                char candidate = content[endOfSignedContentIndex++]; 
                if (('\r' == candidate) || ('\n' == candidate)) { break; }
            }
            return Encoding.UTF8.GetBytes(content.Substring(0, endOfSignedContentIndex));
        }

        protected void ParserInternalError(string message, params object[] args)
        {
            ParsingError("Internal error - " + (message ?? ""), args);
        }

        protected void ParsingError(string message, params object[] args)
        {
            throw new ParsingException(
                InvalidDocumentPrefix + " line #" + CurrentLineNumber.ToString() + " : " + message, args);
        }

        protected void SetContent(string content, string endOfSignedContentKeyWord = null)
        {
            if (null == content) { throw new ArgumentNullException(); }
            _lineEnumerator = content.Split('\n').GetEnumerator();
            if (null != endOfSignedContentKeyWord) {
                _toBeHashed = GetToBeHashedValue(content, endOfSignedContentKeyWord);
            }
        }

        protected bool SplitPair(string item, char splitter, out string key,
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

        protected void SwitchToState(PS newState, bool relaxOrdering = false)
        {
            if (!relaxOrdering && (-1 == newState.CompareTo(_currentState))) {
                ParserInternalError("State switch mismatch from {0} to {1}",
                    _currentState, newState);
            }
            _currentState = newState;
            _performStandardChecks = true;
            return;
        }

        private const string RsaPublicKeyFooter = "-----END RSA PUBLIC KEY-----";
        private const string RsaPublicKeyHeader = "-----BEGIN RSA PUBLIC KEY-----";
        private const string SignatureAlternateFooter = "-----END ID SIGNATURE-----";
        private const string SignatureFooter = "-----END SIGNATURE-----";
        private const string SignatureAlternateHeader = "-----BEGIN ID SIGNATURE-----";
        private const string SignatureHeader = "-----BEGIN SIGNATURE-----";
        private string _currentLineText;
        protected PS _currentState;
        private string[] _items;
        private IEnumerator _lineEnumerator = null;
        protected bool _performStandardChecks = false;
        protected byte[] _toBeHashed;
    }
}
