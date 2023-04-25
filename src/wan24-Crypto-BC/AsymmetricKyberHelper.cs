using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric algorithm helper
    /// </summary>
    public static class AsymmetricKyberHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this KyberParameters param) => param.SessionKeySize switch
        {
            128 => 512,
            192 => 768,
            256 => 1024,
            _ => throw new ArgumentException("Invalid CRYSTALS-Kyber parameters", nameof(param))
        };

        /// <summary>
        /// Get the CRYSTALS-Kyber parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static KyberParameters GetParameters(int keySize) => keySize switch
        {
            512 => KyberParameters.kyber512_aes,
            768 => KyberParameters.kyber768_aes,
            1024 => KyberParameters.kyber1024,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
