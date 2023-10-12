using Org.BouncyCastle.Crypto.Prng;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// XSalsa20 CSRNG
    /// </summary>
    public sealed class XSalsa20Rng : StreamCipherRng
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rng">Internal RNG to use (will be disposed, if possible!)</param>
        /// <param name="bufferSize">Buffer size in bytes (min. <see cref="EncryptionXSalsa20Algorithm.IV_SIZE"/>)</param>
        /// <param name="seedLength">Seed the given RNG with N byte from <see cref="RND"/> (skipped, if <see langword="null"/> or <c>&lt;1</c>)</param>
        public XSalsa20Rng(in IRandomGenerator? rng = null, in int? bufferSize = null, in int? seedLength = 256)//TODO Support ISeedableRng
            : base(EncryptionXSalsa20Algorithm.Instance, rng, bufferSize, seedLength)
        { }
    }
}
