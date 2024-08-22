using wan24.Crypto;
using wan24.Crypto.BC;
using wan24.Crypto.Tests;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Mac_Tests : TestBase
    {
        [TestMethod]
        public async Task All_Tests()
        {
            Assert.IsTrue(MacHelper.Algorithms[MacHmacSha3_256Algorithm.ALGORITHM_NAME] is MacBcHmacSha3_256Algorithm);
            Assert.IsTrue(MacHelper.Algorithms[MacHmacSha3_384Algorithm.ALGORITHM_NAME] is MacBcHmacSha3_384Algorithm);
            Assert.IsTrue(MacHelper.Algorithms[MacHmacSha3_512Algorithm.ALGORITHM_NAME] is MacBcHmacSha3_512Algorithm);
            await MacTests.TestAllAlgorithms();
        }
    }
}
