using Org.BouncyCastle.Pqc.Crypto.Picnic;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Picnic helper
    /// </summary>
    public static class AsymmetricPicnicHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this PicnicParameters param)
        {
            if (param == PicnicParameters.picnicl1full) return 128;
            if (param == PicnicParameters.picnicl3full) return 192;
            if (param == PicnicParameters.picnicl5full) return 256;
            throw new ArgumentException("Invalid Picnic parameters", nameof(param));
        }

        /// <summary>
        /// Get the Picnic parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static PicnicParameters GetParameters(int keySize) => keySize switch
        {
            128 => PicnicParameters.picnicl1full,
            192 => PicnicParameters.picnicl3full,
            256 => PicnicParameters.picnicl5full,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
