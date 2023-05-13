using Microsoft.Extensions.Logging;
using wan24.Core;
using wan24.ObjectValidation;

namespace wan24_Crypto_BC_Tests
{
    [TestClass]
    public class A_Initialization
    {
        [AssemblyInitialize]
        public static void Init(TestContext tc)
        {
            Logging.Logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger("Tests");
            ValidateObject.Logger = (message) => Logging.WriteDebug(message);
            Bootstrap.Async().Wait();
            Logging.WriteDebug("wan24-Crypto-BC Tests initialized");
        }
    }
}
