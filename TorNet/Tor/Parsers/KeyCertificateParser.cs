using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TorNet.Tor.Parsers
{
    internal class KeyCertificateParser : BaseParser<KeyCertificateParser.ParserState>
    {
        static KeyCertificateParser()
        {
            _expectedKeywords = new Dictionary<ParserState, string>();
            _expectedKeywords.Add(ParserState.KeyCertificateVersion, "dir-key-certificate-version");
            _expectedKeywords.Add(ParserState.Address, "dir-address");
            _expectedKeywords.Add(ParserState.Fingerprint, "fingerprint");
            _expectedKeywords.Add(ParserState.IdentityKey, "dir-identity-key");
            _expectedKeywords.Add(ParserState.Published, "dir-key-published");
            _expectedKeywords.Add(ParserState.Expires, "dir-key-expires");
            _expectedKeywords.Add(ParserState.SigningKey, "dir-signing-key");
            _expectedKeywords.Add(ParserState.CrossCertificate, "dir-key-crosscert");
            _expectedKeywords.Add(ParserState.Certification, "dir-key-certification");
        }

        internal KeyCertificateParser()
        {
        }

        protected override string InvalidDocumentPrefix
        {
            get { return "Invalid key certificate document "; }
        }

        protected override Dictionary<ParserState, string> StateExpectations
        {
            get { return _expectedKeywords; }
        }

        internal KeyCertificate Parse(string content)
        {
            bool exceptionTriggered = false;
            KeyCertificate target = new KeyCertificate();

            _currentState = ParserState.KeyCertificateVersion;
            base.SetContent(content, _expectedKeywords[ParserState.Certification]);
            try {
                while ((ParserState.Done != _currentState) && base.AcquireNextLine()) {
                StateSwitched:
                    if (_performStandardChecks) {
                        AssertExpectedKeyword(_currentState, CurrentKeyword);
                    }
                    else { _performStandardChecks = true; }

                    switch (_currentState) {
                        case ParserState.KeyCertificateVersion:
                            if (3 != FetchIntegerItem()) {
                                ParsingError("Version '{0}' not supported.", CurrentItemText);
                            }
                            AssertEndOfLine(ParserState.Address, false, true);
                            break;
                        case ParserState.Address:
                            if (_expectedKeywords[ParserState.Address] != CurrentKeyword) {
                                SwitchToState(ParserState.Fingerprint);
                                goto StateSwitched;
                            }
                            target.EndPoint = FetchIPEndPoint();
                            AssertEndOfLine(ParserState.Fingerprint);
                            break;
                        case ParserState.Fingerprint:
                            target.Fingerprint = FetchHexadecimalEncodedString();
                            AssertEndOfLine(ParserState.Published);
                            break;
                        case ParserState.Published:
                            target.Published = FetchTimestampItem();
                            AssertEndOfLine(ParserState.Expires);
                            break;
                        case ParserState.Expires:
                            target.Expires = FetchTimestampItem();
                            AssertEndOfLine(ParserState.SigningKey);
                            break;
                        case ParserState.SigningKey:
                            target.SigningKey = FetchRsaPublicKey();
                            AssertEndOfLine(ParserState.CrossCertificate);
                            break;
                        case ParserState.CrossCertificate:
                            target.CrossSignature = FetchSignature(true);
                            AssertEndOfLine(ParserState.Certification);
                            break;
                        case ParserState.Certification:
                            throw new NotImplementedException();
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
                    if (base.AcquireNextLine()) {
                        ParsingError("End state reached with remaining lines.");
                    }
                }
            }
            throw new NotImplementedException();
        }

        /// <summary>Should we land here, there is a severe logical error.</summary>
        protected void WTF()
        {
            ParsingError("WTF");
        }

        private ParserState _currentState;
        private static Dictionary<ParserState, string> _expectedKeywords;

        /// <summary>The state value describes which element is to be handled
        /// during next loop. WARNING : Do not reorder. There is a check on some
        /// variables of this type for monotonic increasing value.</summary>
        internal enum ParserState
        {
            Undefined,
            KeyCertificateVersion,
            Address,
            Fingerprint,
            IdentityKey,
            Published,
            Expires,
            SigningKey,
            CrossCertificate,
            Certification,
            Done
        }
    }
}
