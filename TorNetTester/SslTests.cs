using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using TorNet;

namespace TorNetTester
{
    [TestClass]
    public class SslTests
    {
        public SslTests()
        {
        }

        public TestContext TestContext { get; set; }

        #region Additional attributes
        // One time init
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // One time cleanup
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Triggered before each test
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Triggered after each test
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        #endregion

        [TestMethod]
        public void TestLocalhost443()
        {
            new SslSocket("localhost", 443);
            return;
        }
    }
}
