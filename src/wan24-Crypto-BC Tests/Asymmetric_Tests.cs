using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Asymmetric_Tests
    {
        [TestMethod]
        public void AllAlgo_Tests() => AsymmetricTests.TestAllAlgorithms();
    }
}
