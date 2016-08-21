using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using TorNet;
using TorNet.Tor;
using TorNet.Tor.Parsers;

namespace TorNetTester
{
    [TestClass]
    public class GeneralUseUrlsTests
    {
        public GeneralUseUrlsTests()
        {
        }

        public TestContext TestContext { get; set; }

        #region Attributs de tests supplémentaires
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        [TestInitialize()]
        public void MyTestInitialize()
        {
            switch(TestContext.TestName) {
                case "RetrieveKeyCertificate":
                    _targetAuthority = Authority.GetRandomAuthority();
                    break;
                default:
                    break;
            }
        }

        // [TestCleanup()]
        // public void MyTestCleanup() { }
        #endregion

        [TestMethod]
        public void RetrieveKeyCertificate()
        {
            string rawCertificateContent =
                _targetAuthority.GetKeyCertificate(
                    RetrievalOptions.UseCache | RetrievalOptions.ForceDownload);
            return;
        }

        [TestMethod]
        public void RetrieveMostRecentV3Consensus()
        {
            string relativePath = Encoding.ASCII.GetString(
                WellKnownUrlRetriever.Retrieve(
                    WellKnownUrlRetriever.Document.MostRecentV3Consensus));
            string mostRecentCompressedV3Consensus = Encoding.ASCII.GetString(
                Authority.DownloadFromRandomAuthority(relativePath, true));
            string compressedContentFileName = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Personal),
                "v3Consensus.z");
            return;
        }

        [TestMethod]
        public void UncompressManuallyDownloadedContent()
        {
            if (!File.Exists(Helpers.DecompressionTestFilePath)) {
                throw new InvalidOperationException();
            }
            byte[] compressedContent;
            using(FileStream input = File.Open(Helpers.DecompressionTestFilePath, FileMode.Open, FileAccess.Read)) {
                compressedContent = new byte[(int)input.Length];
                input.Read(compressedContent, 0, compressedContent.Length);
            }
            byte[] rawContent = Helpers.Uncompress(compressedContent);
            string stringContent = Encoding.ASCII.GetString(rawContent);
            return;
        }

        private const string compressedConsensusFileName = "v3Consensus.z";
        private Authority _targetAuthority;
    }
}
