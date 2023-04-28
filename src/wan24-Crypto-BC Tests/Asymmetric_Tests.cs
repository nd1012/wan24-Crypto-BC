using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Asymmetric_Tests
    {

        static Asymmetric_Tests() => wan24.Crypto.BC.Bootstrap.Boot();

        [TestMethod]
        public void AllAlgo_Tests() => AsymmetricTests.TestAllAlgorithms();
    }
}
