using System;
using System.Collections.Generic;

using TorNet.Cryptography;

namespace TorNet.Tor.Parsers
{
    internal class KeyCertificateParser : BaseParser<KeyCertificateParser.ParserState>
    {
        static KeyCertificateParser()
        {
            _expectedKeywords = new Dictionary<string, ItemDescriptor<ParserState>>();
            _expectedKeywords.Add("dir-key-certificate-version",
                new ItemDescriptor<ParserState>(ParserState.KeyCertificateVersion,
                    ItemMultiplicity.AtStartExactlyOnce));
            _expectedKeywords.Add("dir-address",
                new ItemDescriptor<ParserState>(ParserState.Address,
                    ItemMultiplicity.AtMotOnce));
            _expectedKeywords.Add("fingerprint",
                new ItemDescriptor<ParserState>(ParserState.Fingerprint,
                    ItemMultiplicity.ExactlyOnce));
            _expectedKeywords.Add("dir-identity-key",
                new ItemDescriptor<ParserState>(ParserState.IdentityKey,
                    ItemMultiplicity.ExactlyOnce));
            _expectedKeywords.Add("dir-key-published",
                new ItemDescriptor<ParserState>(ParserState.Published,
                    ItemMultiplicity.ExactlyOnce));
            _expectedKeywords.Add("dir-key-expires",
                new ItemDescriptor<ParserState>(ParserState.Expires,
                    ItemMultiplicity.ExactlyOnce));
            _expectedKeywords.Add("dir-signing-key",
                new ItemDescriptor<ParserState>(ParserState.SigningKey,
                    ItemMultiplicity.ExactlyOnce));
            _expectedKeywords.Add("dir-key-crosscert",
                new ItemDescriptor<ParserState>(ParserState.CrossCertificate,
                    ItemMultiplicity.ExactlyOnce));
            _expectedKeywords.Add("dir-key-certification",
                new ItemDescriptor<ParserState>(ParserState.Certification,
                    ItemMultiplicity.AtEndExactlyOnce));
        }

        internal KeyCertificateParser()
        {
            return;
        }

        protected override string InvalidDocumentPrefix
        {
            get { return "Invalid key certificate document "; }
        }

        protected override Dictionary<string, ItemDescriptor<ParserState>> StateExpectations
        {
            get { return _expectedKeywords; }
        }

        internal KeyCertificate Parse(string content)
        {
            bool exceptionTriggered = false;
            KeyCertificate result = new KeyCertificate();

            _currentState = ParserState.KeyCertificateVersion;
            base.SetContent(content, _expectedKeywords[ParserState.Certification]);
            try {
                _performStandardChecks = true;
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
                            result.EndPoint = FetchIPEndPoint();
                            AssertEndOfLine(ParserState.Fingerprint);
                            break;
                        case ParserState.Fingerprint:
                            result.Fingerprint = FetchHexadecimalEncodedString();
                            AssertEndOfLine(ParserState.Published);
                            break;
                        case ParserState.Published:
                            result.Published = FetchTimestampItem();
                            AssertEndOfLine(ParserState.Expires);
                            break;
                        case ParserState.Expires:
                            result.Expires = FetchTimestampItem();
                            AssertEndOfLine(ParserState.IdentityKey);
                            break;
                        case ParserState.IdentityKey:
                            result.IdentityKey = FetchRsaPublicKey();
                            AssertEndOfLine(ParserState.SigningKey);
                            break;
                        case ParserState.SigningKey:
                            result.SigningKey = FetchRsaPublicKey();
                            AssertEndOfLine(ParserState.CrossCertificate);
                            break;
                        case ParserState.CrossCertificate:
                            result.CrossSignature = FetchSignature(true);
                            AssertEndOfLine(ParserState.Certification);
                            break;
                        case ParserState.Certification:
                            // TODO : This must be extracted from this method and performed during
                            // a later step.
                            if (CaptureOptionalItem()) {
                                ParsingError("Key certificate signature entry contains extra parameters.");
                            }
                            result.Signature = FetchSignature();
                            AssertEndOfLine(ParserState.Done);
                            result.ToBeHashed = base._toBeHashed;
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

        private static Dictionary<string, ItemDescriptor<ParserState>> _expectedKeywords;

        /// <summary>The state value describes which element is to be handled
        /// during next loop. WARNING : Do not reorder. There is a check on some
        /// variables of this type for monotonic increasing value.</summary>
        internal enum ParserState
        {
            Undefined,
            KeyCertificateVersion,
            Address,
            Fingerprint,
            Published,
            Expires,
            IdentityKey,
            SigningKey,
            CrossCertificate,
            Certification,
            Done
        }
    }
}
