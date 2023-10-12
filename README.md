# wan24-Crypto-BC

This library adopts 
[The Bouncy Castle Cryptography Library For .NET](https://github.com/bcgit/bc-csharp) 
to [wan24-Crypto](https://www.nuget.org/packages/wan24-Crypto/) and extends 
the `wan24-Crypto` library with these algorithms:

| Algorithm | ID | Name |
| --- | --- | --- |
| **Asymmetric** |  |  |
| CRYSTALS-Kyber | 2 | CRYSTALSKYBER |
| CRYSTALS-Dilithium | 3 | CRYSTALSDILITHIUM |
| FALCON | 4 | FALCON |
| SPHINCS+ | 5 | SPHINCSPLUS |
| FrodoKEM* | 6 | FRODOKEM |
| **Symmetric** |  |  |
| ChaCha20 | 1 | CHACHA20 |
| XSalsa20 | 2 | XSALSA20 |
| AES-256-GCM AEAD (128 bit MAC) | 3 | AES256GCM |
| Serpent 256 CBC (ISO10126 padding) | 5 | SERPENT256CBC |
| Serpent 256 GCM AEAD (128 bit MAC) | 6 | SERPENT256GCM |
| Twofish 256 CBC (ISO10126 padding) | 7 | TWOFISH256CBC |
| Twofish 256 GCM AEAD (128 bit MAC) | 8 | TWOFISH256GCM |
| **Hashing** |  |  |
| SHA3-256 | 5 | SHA3-256 |
| SHA3-384 | 6 | SHA3-384 |
| SHA3-512 | 7 | SHA3-512 |
| **MAC** |  |  |
| HMAC-SHA3-256 | 4 | HMAC-SHA3-256 |
| HMAC-SHA3-384 | 5 | HMAC-SHA3-384 |
| HMAC-SHA3-512 | 6 | HMAC-SHA3-512 |

**NOTE**: FrodoKEM is currently disabled, 'cause there seems to be a bug 
(missing code) in the Bouncy Castle library for FrodoKEM.

## How to get it

This library is available as 
[NuGet package](https://www.nuget.org/packages/wan24-Crypto-BC/).

## Usage

In case you don't use the `wan24-Core` bootstrapper logic, you need to 
initialize the Bouncy Castle extension first, before you can use it:

```cs
wan24.Crypto.BC.Bootstrapper.Boot();
```

This will register the algorithms to the `wan24-Crypto` library.

To set Bouncy Castle defaults as `wan24-Crypto` defaults:

```cs
BouncyCastle.SetDefaults();
```

Per default the current `wan24-Crypto` default will be set as counter 
algorithms to `HybridAlgorithmHelper`.

Some algorithms of the `wan24-Crypto` library are not available on some 
platforms, that's why they need to be replaced in order to be used:

| `wan24-Crypto` | `wan24-Crypto-BC` |
| -------------- | ----------------- |
| `EncryptionAes256CbcAlgorithm` | `EncryptionBcAes256CbcAlgorithm` |

To replace all of them:

```cs
BouncyCastle.ReplaceNetAlgorithms();
```

## Post quantum safety

These algorithms are designed for post quantum cryptography:

- CRYSTALS-Kyber (key exchange)
- CRYSTALS-Dilithium (signature)
- FALCON (signature)
- SPHINCS+ (signature)
- FrodoKEM (key exchange)

Normally you want to use them in hybrid mode as counter algorithm for 
extending a default algorithm of the `wan24-Crypto` package. To do this per 
default:

```cs
// Enable the post quantum algorithms as counter-defaults
CryptoHelper.ForcePostQuantumSafety();
```

This will use these algorithms as counter algorithms for asymmetric 
cryptography, in case you didn't define other post quantum algorithms already:

- CRYSTALS-Kyber (key exchange)
- CRYSTALS-Dilithium (signature)

For using other algorithms instead:

```cs
// FALCON
HybridAlgorithmHelper.SignatureAlgorithm = 
    AsymmetricHelper.GetAlgorithm(AsymmetricFalconAlgorithm.ALGORITHM_NAME);

// SPHINCS+
HybridAlgorithmHelper.SignatureAlgorithm = 
    AsymmetricHelper.GetAlgorithm(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME);

// FrodoKEM
HybridAlgorithmHelper.KeyExchangeAlgorithm = 
    AsymmetricHelper.GetAlgorithm(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME);
```

The counter algorithm will come in effect, if you use asymmetric keys for 
encryption:

```cs
// Create options having a counter private key
CryptoOptions options = EncryptionHelper.GetDefaultOptions();
options.SetCounterPrivateKey(yourKyberPrivateKey);

// Encrypt using the options and your normal private key
byte[] cipherData = rawData.Encrypt(yourNormalPrivateKey, options);
rawData = cipherData.Decrypt(yourNormalPrivateKey, options);
```

And for signature:

```cs
// Create options having a counter private key
CryptoOptions options = AsymmetricHelper.GetDefaultSignatureOptions();
options.SetCounterPrivateKey(yourDilithiumPrivateKey);

// Sign using the options and your normal private key
SignatureContainer signature = dataToSign.Sign(yourNormalPrivateKey, options: options);
```

## Algorithm parameters used

For CRYSTALS-Kyber and CRYSTALS-Dilithium the AES parameters are being used. 
When using SPHINCS+, the Haraka F hashing parameters will be used. For 
FrodoKEM the AES parameters will be used.

## Random data provider

The `RandomDataProvider` is a `RandomDataGenerator` which provides added seed 
data to `OnSeed` attached event handlers. It uses the `ChaCha20Rng` in 
combination with `RND` of `wan24-Crypto` to produce cryptographic secure 
random data (CSRNG). An instance may be set as `RND.Generator` singleton 
random data generator for all consumers (like key generators etc.).

`RandomDataProvider` can be customized by extending the type. Pregnant methods 
are virtual and can be overridden. Since the type is a `HostedServiceBase`, it 
can be used in modern .NET app environments. And since it implements the 
`IRandomGenerator` interface of Bouncy Castle, it can be used as secure random 
data source for all Bouncy Castle algorithms (like key generators) also.

By calling the `CreateFork(Async)` method, you can create an attached 
instance, which will be initialized with a random seed generated by the parent 
instance and consumes the provided seeds from the parent automatically.

**NOTE**: Don't forget to dispose an unused `RandomDataProvider` instance!

**CAUTION**: There is a patent (US10402172B1) which comes into play, if you 
plan to create a Random or Entrophy as a Service (R/EaaS) application, 
especially when using QRNG entrophy or sequences. Read that document carefully 
to avoid disappointments. The patent can't forbid to create and run an 
internal R/EaaS application, but it can deny any distribution of R/EaaS 
appliances, their generated random sequences, and even keys (for a PKI, for 
example) which have been generated using such random sequences, even those 
have been aggregated with a PRNG, CSRNG or any other RNG or enthrophy source. 
Sad (in my opinion), but fact: All network communicated random based sequences 
in any R/EaaS manner are denied by this patent. Only local usage on a single 
mashine is still possible, but any data which comes in touch with a random 
sequence in any way, is denied to be extracted from that system over a 
network. The only way to get around that is to use a quantum physical 
hardware, which is linked to another quantum physical hardware at another 
location, and doesn't require classical network communication for exchanging 
information (QKD). To sum that mess up: You may use the `RandomDataProvider` 
on a local system **_only_**, unless you use quantum physical hardware as 
described. Fortunately the patent holder (which has a past in the CIA) offers 
everything to go, and seems to stay the only source until at last the year 
2039, if the patent offices or curts won't undo that big mistake to confirm 
that patent in the published form.

You may use R/EaaS in regions and for data which is being communicated in 
regions where the patent doesn't have an effect, and switch back to classical 
P/CSRNG for communications with any patent affected regions - or use the 
patent holders hard- and software (from within that regions).

## Stream cipher RNG

The `StreamCipherRng` uses any stream cipher to encrypt the generated random 
bytes of an underlaying PRNG using a random key. The result is a CSRNG. These 
stream ciphers are available with `wan24-Crypto-BC`, but you could use any 
other stream cipher (but not AEAD implementations!) also:

- ChaCha20 - `ChaCha20Rng`
- XSalsa20 - `XSalsa20Rng`

If you didn't specify an underlaying PRNG, Bouncy Castle's 
`VmpcRandomGenerator` will be used and seeded using 256 bytes from `RND`.

The final CSRNG implements `IRandomGenerator` for use with Bouncy Castle, and 
also `ISeedableRng` for use with `RND` (as seed consumer, for example).

**NOTE**: A `StreamCipherRng` needs to be disposed after use!

You can use the resulting CSRNG as default RNG for `RND`:

```cs
ChaCha20Rng csrng = new();

// Enable automatic seeding
RND.SeedConsumer = csrng;

// Use as default CSRNG
RND.FillBytes = csrng.GetBytes;
RND.FillBytesAsync = csrng.GetBytesAsync;
```

**NOTE**: When setting the `RND.FillBytes(Async)` callbacks, they may not be 
used, if `/dev/urandom` was preferred. To disable `/dev/urandom`, set 
`RND.UseDevUrandom` and `RND.RequireDevUrandom` to `false` also.

**NOTE**: Currently only stream ciphers are supported, because the cipher RNG 
implementation doesn't buffer pre-generated random data.
