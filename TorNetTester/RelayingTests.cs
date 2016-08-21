using Microsoft.VisualStudio.TestTools.UnitTesting;

using TorNet.Tor;

namespace TorNetTester
{
    [TestClass]
    public class RelayingTests
    {
        public RelayingTests()
        {
        }

        public TestContext TestContext { get; set; }

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

        [TestMethod]
        public void BuildOneHopRelay()
        {
            // Retrieve current consensus either from cache or from the network.
            Consensus consensus = Consensus.Fetch(RetrievalOptions.None);
            TorSocket socket = new TorSocket();
            using (Circuit circuit = new Circuit(socket)) {
                circuit.Create(consensus.GetRandomRouter());
            }
        }
    }
}
