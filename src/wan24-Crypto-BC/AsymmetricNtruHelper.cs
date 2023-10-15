using Org.BouncyCastle.Pqc.Crypto.Ntru;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// NTRU helper
    /// </summary>
    public static class AsymmetricNtruHelper
    {
        /// <summary>
        /// Get the key size in bits
        /// </summary>
        /// <param name="param">Parameters</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(this NtruParameters param)
        {
            if (param == NtruParameters.NtruHps2048509) return 509;
            if (param == NtruParameters.NtruHps2048677) return 677;
            if (param == NtruParameters.NtruHps4096821) return 821;
            if (param == NtruParameters.NtruHrss701) return 701;
            throw new ArgumentException("Invalid NTRU parameters", nameof(param));
        }

        /// <summary>
        /// Get the NTRU parameters
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        /// <returns>Parameters</returns>
        public static NtruParameters GetParameters(int keySize) => keySize switch
        {
            509 => NtruParameters.NtruHps2048509,
            677 => NtruParameters.NtruHps2048677,
            821 => NtruParameters.NtruHps4096821,
            701 => NtruParameters.NtruHrss701,
            _ => throw new ArgumentException("Invalid key size", nameof(keySize))
        };
    }
}
