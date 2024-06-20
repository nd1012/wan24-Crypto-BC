using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Auto seed RNG seeding types enumeration
    /// </summary>
    public enum AutoSeedRngTypes : int
    {
        /// <summary>
        /// Feed fresh seed after RND was consumed
        /// </summary>
        [DisplayText("Feed fresh seed after RND was consumed")]
        AfterRndConsumed = 0,
        /// <summary>
        /// Feed fresh seed permanently (slow seed provider)
        /// </summary>
        [DisplayText("Feed fresh seed permanent")]
        Permanent = 1,
        /// <summary>
        /// Interval seeding
        /// </summary>
        [DisplayText("Feed fresh seed in an interval")]
        Interval = 2
    }
}
