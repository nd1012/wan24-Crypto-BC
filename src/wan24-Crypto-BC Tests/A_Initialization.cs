using wan24.Core;
using wan24.Crypto.BC;
using wan24.Crypto.Tests;

namespace wan24_Crypto_BC_Tests
{
    [TestClass]
    public class A_Initialization
    {
        [AssemblyInitialize]
        public static void Init(TestContext tc)
        {
            wan24.Tests.TestsInitialization.Init(tc);
            SharedTests.Initialize();
            BouncyCastle.ReplaceNetAlgorithms();
            Logging.WriteDebug("wan24-Crypto-BC Tests initialized");
        }
    }
}
