using wan24.Crypto;
using wan24.Crypto.BC;
using wan24.Crypto.Tests;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Asymmetric_Tests : TestBase
    {
        [TestMethod]
        public void AllAlgo_Tests()
        {
            Assert.IsTrue(AsymmetricHelper.Algorithms[AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME] is AsymmetricBcEcDiffieHellmanAlgorithm);
            Assert.IsTrue(AsymmetricHelper.Algorithms[AsymmetricEcDsaAlgorithm.ALGORITHM_NAME] is AsymmetricBcEcDsaAlgorithm);
            AsymmetricTests.TestAllAlgorithms();
        }
    }
}
