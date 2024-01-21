using Microsoft.Extensions.Logging;
using wan24.Core;
using wan24.Crypto.BC;
using wan24.Crypto.Tests;
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
            TypeHelper.Instance.AddAssemblies(typeof(wan24.Crypto.BC.Bootstrap).Assembly);
            wan24.Core.Bootstrap.Async().Wait();
            DisposableBase.CreateStackInfo = true;
            DisposableRecordBase.CreateStackInfo = true;
            ErrorHandling.ErrorHandler = (info) =>
            {
                if (info.Exception is StackInfoException six) Logging.WriteError(six.StackInfo.Stack);
            };
            SharedTests.Initialize();
            BouncyCastle.ReplaceNetAlgorithms();
            Logging.WriteDebug("wan24-Crypto-BC Tests initialized");
        }
    }
}
