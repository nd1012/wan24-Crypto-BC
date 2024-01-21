using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Hybrid_Tests
    {
        [TestMethod]
        public void Asymmetric_Tests()
        {
            HybridTests.AllAsymmetricTests();
        }

        [TestMethod]
        public void Sync_Encryption_Tests()
        {
            return;
            HybridTests.AllSyncEncryptionTests();
        }

        [TestMethod]
        public async Task Async_Encryption_Tests()
        {
            return;
            await HybridTests.AllAsyncEncryptionTests();
        }
    }
}
