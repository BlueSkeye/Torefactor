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

        private TestContext testContextInstance;

        public TestContext TestContext { get; set; }

        #region Attributs de tests supplémentaires
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        #endregion

        [TestMethod]
        public void RetrieveMostRecentV3Consensus()
        {
            string relativePath = WellKnownUrlRetriever.Retrieve(
                WellKnownUrlRetriever.Document.MostRecentV3Consensus);
            string mostRecentCompressedV3Consensus =
                Authority.DownloadFromRandomAuthority(relativePath, true);
            string compressedContentFileName = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Personal),
                "v3Consensus.z");
            return;
        }

        private const string compressedConsensusFileName = "v3Consensus.z";

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
    }
}
