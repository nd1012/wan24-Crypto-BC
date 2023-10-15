using Org.BouncyCastle.Crypto.Prng;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Interface for a seedable Bouncy Castle supporting RNG
    /// </summary>
    public interface IBouncyCastleRng : IRandomGenerator, ISeedableRng
    {
    }
}
