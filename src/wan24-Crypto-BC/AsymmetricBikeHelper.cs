using Org.BouncyCastle.Pqc.Crypto.Bike;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// BIKE asymmetric algorithm helper
    /// </summary>
    public static class AsymmetricBikeHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this BikeParameters param)
        {
            if (param == BikeParameters.bike128) return 128;
            if (param == BikeParameters.bike192) return 192;
            if (param == BikeParameters.bike256) return 256;
            throw new ArgumentException("Invalid BIKE parameters", nameof(param));
        }

        /// <summary>
        /// Get the BIKE parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static BikeParameters GetParameters(int keySize) => keySize switch
        {
            128 => BikeParameters.bike128,
            192 => BikeParameters.bike192,
            256 => BikeParameters.bike256,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
