using wan24.Crypto;
using wan24.Crypto.BC;
using wan24.Crypto.Tests;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Hashing_Tests : TestBase
    {
        [TestMethod]
        public async Task All_Tests()
        {
            Assert.IsTrue(HashHelper.Algorithms[HashSha3_256Algorithm.ALGORITHM_NAME] is HashBcSha3_256Algorithm);
            Assert.IsTrue(HashHelper.Algorithms[HashSha3_384Algorithm.ALGORITHM_NAME] is HashBcSha3_384Algorithm);
            Assert.IsTrue(HashHelper.Algorithms[HashSha3_512Algorithm.ALGORITHM_NAME] is HashBcSha3_512Algorithm);
            Assert.IsTrue(HashHelper.Algorithms[HashShake128Algorithm.ALGORITHM_NAME] is HashBcShake128Algorithm);
            Assert.IsTrue(HashHelper.Algorithms[HashShake256Algorithm.ALGORITHM_NAME] is HashBcShake256Algorithm);
            await HashingTests.TestAllAlgorithms();
        }
    }
}
