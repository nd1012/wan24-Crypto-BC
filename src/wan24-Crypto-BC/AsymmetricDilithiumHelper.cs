using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium helper
    /// </summary>
    public static class AsymmetricDilithiumHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this DilithiumParameters param)
        {
            if (param == DilithiumParameters.Dilithium2) return 512;
            if (param == DilithiumParameters.Dilithium3) return 768;
            if (param == DilithiumParameters.Dilithium5) return 1024;
            throw new ArgumentException("Invalid CRYSTALS-Dilithium parameters", nameof(param));
        }

        /// <summary>
        /// Get the CRYSTALS-Dilithium parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static DilithiumParameters GetParameters(int keySize) => keySize switch
        {
            512 => DilithiumParameters.Dilithium2,
            768 => DilithiumParameters.Dilithium3,
            1024 => DilithiumParameters.Dilithium5,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
