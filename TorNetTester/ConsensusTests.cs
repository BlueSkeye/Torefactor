using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using TorNet;
using TorNet.Tor;

namespace TorNetTester
{
    [TestClass]
    public class ConsensusTests
    {
        public ConsensusTests()
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
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        /// <summary>Fetch consensus ignoring cache.</summary>
        [TestMethod]
        public void DownloadConsensus()
        {
            Consensus consensus = new Consensus(Consensus.Options.ForceDownload);
            return;
        }

        /// <summary>Buld consensus from cached value.</summary>
        [TestMethod]
        public void BuildConsensusFromCache()
        {
            Consensus consensus = new Consensus(Consensus.Options.UseCache);
            return;
        }
    }
}
