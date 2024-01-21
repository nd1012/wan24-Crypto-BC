using wan24.Crypto;
using wan24.Crypto.BC;
using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Encryption_Tests
    {
        [TestMethod]
        public async Task All_Tests()
        {
            Assert.IsTrue(EncryptionHelper.Algorithms[EncryptionAes256CbcAlgorithm.ALGORITHM_NAME] is EncryptionBcAes256CbcAlgorithm);
            await EncryptionTests.TestAllAlgorithms();
        }
    }
}
