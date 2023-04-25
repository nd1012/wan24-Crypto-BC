using wan24.Core;

[assembly: Bootstrapper(typeof(wan24.Crypto.BC.Bootstrap), nameof(wan24.Crypto.BC.Bootstrap.Boot))]

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bootstrapper
    /// </summary>
    public static class Bootstrap
    {
        /// <summary>
        /// Boot
        /// </summary>
        public static void Boot()
        {
            AsymmetricHelper.Algorithms[AsymmetricKyberAlgorithm.ALGORITHM_NAME] = new AsymmetricKyberAlgorithm();
            //TODO Register other algorithms, too
            CryptoHelper.OnForcePostQuantum += (e) =>
            {
                if (!(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? false))
                    HybridAlgorithmHelper.KeyExchangeAlgorithm = AsymmetricHelper.GetAlgorithm(AsymmetricKyberAlgorithm.ALGORITHM_NAME);
                //TODO Register signature algorithm, too
            };
        }
    }
}
