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
| NTRUEncrypt* | 7 | NTRUENCRYPT |
| Ed25519 | 8 | ED25519 |
| Ed448 | 9 | ED448 |
| **Symmetric** |  |  |
| ChaCha20 | 1 | CHACHA20 |
| XSalsa20 | 2 | XSALSA20 |
| AES-256-GCM AEAD (128 bit MAC) | 3 | AES256GCM |
| Serpent 256 CBC (ISO10126 padding) | 5 | SERPENT256CBC |
| Serpent 256 GCM AEAD (128 bit MAC) | 6 | SERPENT256GCM |
| Twofish 256 CBC (ISO10126 padding) | 7 | TWOFISH256CBC |
| Twofish 256 GCM AEAD (128 bit MAC) | 8 | TWOFISH256GCM |

**NOTE**: FrodoKEM and NTRUEncrypt are currently disabled, 'cause there seems 
to be a bug (missing code) in the Bouncy Castle library for 
exporting/importing private keys (at last).

NTRUSign is currently not implemented, 'cause it'd require the using code to 
be GPL licensed. This algorithm may be included in a separate package which is 
licensed using the GPL license (to avoid misunderstandings) in the future.

## How to get it

This library is available as 
[NuGet package](https://www.nuget.org/packages/wan24-Crypto-BC/).

## Usage

In case you don't use the `wan24-Core` bootstrapper logic, you need to 
initialize the Bouncy Castle extension first, before you can use it:

```cs
wan24.Crypto.BC.Bootstrap.Boot();
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
| `HashSha3_256Algorithm` | `HashBcSha3_256Algorithm` |
| `HashSha3_384Algorithm` | `HashBcSha3_384Algorithm` |
| `HashSha3_512Algorithm` | `HashBcSha3_512Algorithm` |
| `MacHmacSha3_256Algorithm` | `MacBcHmacSha3_256Algorithm` |
| `MacHmacSha3_384Algorithm` | `MacBcHmacSha3_384Algorithm` |
| `MacHmacSha3_512Algorithm` | `MacBcHmacSha3_512Algorithm` |
| `HashShake128Algorithm` | `HashBcShake128Algorithm` |
| `HashShake256Algorithm` | `HashBcShake256Algorithm` |

To replace all of them:

```cs
BouncyCastle.ReplaceNetAlgorithms();
```

**NOTE**: The Shake128/256 replacements don't support variable output length 
and use the default output length of the `wan24-Crypto` implementations 
instead.

## Post quantum safety

These algorithms are designed for post quantum cryptography:

- CRYSTALS-Kyber (key exchange)
- CRYSTALS-Dilithium (signature)
- FALCON (signature)
- SPHINCS+ (signature)
- FrodoKEM (key exchange)
- NTRU (key exchange)

Normally you want to use them in hybrid mode and use classical algorithms of 
the `wan24-Crypto` package as counter algorithm. To do this per default:

```cs
// Enable the post quantum algorithms as (counter-)defaults
CryptoHelper.ForcePostQuantumSafety();
```

This will use these algorithms as (counter) algorithms for asymmetric 
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
data to `OnSeed(Async)` attached event handlers. It uses the `ChaCha20Rng` in 
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
plan to create a Random or Entropy as a Service (R/EaaS) application, 
especially when using QRNG entropy. Read that document carefully to avoid 
disappointments.

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
used, if `/dev/random` was preferred. To disable `/dev/random`, set 
`RND.UseDevRandom` and `RND.RequireDevRandom` to `false` also.

**NOTE**: Currently only stream ciphers are supported, because the cipher RNG 
implementation doesn't buffer pre-generated random data.

## Ed448-Goldilocks

Just a short note on edwards448: Private and public keys have a different key 
size: The private key has 456 bit, while the public key has 448 bit. Both key 
sizes are supported for key generation and result in the same key sizes for 
the private (456 bit) and the public (448 bit) key. The private key of a key 
pair will always identify with 456 bit, while the public key will always 
identify with 448 bit - no matter which key size was chosen for key pair 
generation.

The Ed448 signature is context based, but currently only an empty byte array 
is being used as context data. Ed25519 uses SHA-512 for hashing, Ed448 uses 
Shake256. Anyway, since you can define the hash algorithm to use using the 
`CryptoOptions`, there'll always be a hash of a hash (from `CryptoOptions`) 
which is going to be signed, finally.
