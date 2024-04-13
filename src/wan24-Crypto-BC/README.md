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
| FrodoKEM | 6 | FRODOKEM |
| NTRUEncrypt | 7 | NTRUENCRYPT |
| Ed25519 | 8 | ED25519 |
| Ed448 | 9 | ED448 |
| X25519 | 10 | X25519 |
| X448 | 11 | X448 |
| XEd25519 | 12 | XED25519 |
| XEd448 | 13 | XED448 |
| Streamlined NTRU Prime | 14 | SNTRUP |
| BIKE | 15 | BIKE |
| HQC | 16 | HQC |
| Picnic | 17 | PICNIC |
| **Symmetric** |  |  |
| ChaCha20 | 1 | CHACHA20 |
| XSalsa20 | 2 | XSALSA20 |
| AES-256-GCM AEAD (128 bit MAC) | 3 | AES256GCM |
| Serpent 256 CBC (ISO10126 padding) | 5 | SERPENT256CBC |
| Serpent 256 GCM AEAD (128 bit MAC) | 6 | SERPENT256GCM |
| Twofish 256 CBC (ISO10126 padding) | 7 | TWOFISH256CBC |
| Twofish 256 GCM AEAD (128 bit MAC) | 8 | TWOFISH256GCM |

Main goals of this extension library are to make `wan24-Crypto` usable on all 
platforms and extend its algorithms by PQC algorithms and other non-PQC 
algorithms, which are not available from .NET, but implemented in the Bouncy 
Castle library.

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

### `wan24-Crypto` algorithm replacement

Some algorithms of the `wan24-Crypto` library are not available on some 
platforms, that's why they need to be replaced in order to be used:

| `wan24-Crypto` | `wan24-Crypto-BC` |
| -------------- | ----------------- |
| `AsymmetricEcDiffieHellmanAlgorithm` | `AsymmetricBcEcDiffieHellmanAlgorithm` |
| `AsymmetricEcDsaAlgorithm` | `AsymmetricBcEcDsaAlgorithm` |
| `EncryptionAes256CbcAlgorithm` | `EncryptionBcAes256CbcAlgorithm` |
| `HashShake128Algorithm` | `HashBcShake128Algorithm` |
| `HashShake256Algorithm` | `HashBcShake256Algorithm` |
| `HashSha3_256Algorithm` | `HashBcSha3_256Algorithm` |
| `HashSha3_384Algorithm` | `HashBcSha3_384Algorithm` |
| `HashSha3_512Algorithm` | `HashBcSha3_512Algorithm` |
| `MacHmacSha3_256Algorithm` | `MacBcHmacSha3_256Algorithm` |
| `MacHmacSha3_384Algorithm` | `MacBcHmacSha3_384Algorithm` |
| `MacHmacSha3_512Algorithm` | `MacBcHmacSha3_512Algorithm` |

To replace all of them:

```cs
BouncyCastle.ReplaceNetAlgorithms();
```

**NOTE**: The Shake128/256 replacements don't support variable output length 
and use the default output length of the `wan24-Crypto` implementations 
instead. The `NetShake128/256HashAlgorithmAdapter` can't be replaced for this 
reason.

In order to override the .NET default SHA3 hash and HMAC algorithms, you can 
call:

```cs
BouncyCastle.RegisterNetAlgorithms();
```

This will use Bouncy Castle SHA3 implementations for the .NET implemented SHA3 
hash algorithms:

| Name | Type |
| ---- | ---- |
| SHA3-256 | `HashBcSha3_256.SHA3_256` |
| SHA3-384 | `HashBcSha3_384.SHA3_384` |
| SHA3-512 | `HashBcSha3_512.SHA3_512` |
| HMACSHA3-256 | `MacBcHmacSha3_256.HMACSHA3_256` |
| HMACSHA3-384 | `MacBcHmacSha3_384.HMACSHA3_384` |
| HMACSHA3-512 | `MacBcHmacSha3_512.HMACSHA3_512` |

This step is required, if you want to ensure that whenever a .NET crypto type 
or any 3rd party crypto type requests a SHA3 hash or HMAC instance using the 
static `HashAlgorithm.Create("NAME")` or `KeyedHashAlgorithm.Create("NAME")` 
methods.

### Use as default algorithms

To set Bouncy Castle defaults as `wan24-Crypto` defaults:

```cs
BouncyCastle.SetDefaults();
```

Per default the current `wan24-Crypto` default will be set as counter 
algorithms to `HybridAlgorithmHelper`.

Current Bouncy Castle default algorithms are:

| Usage | Algorithm |
| ----- | --------- |
| Key exchange | NTRUEncrypt |
| Signature | CRYSTALS-Dilithium |
| Encryption | Serpent 256 bit CBC |
| PAKE encryption | Serpent 256 bit GCM |

## Post quantum safety

These asymmetric algorithms are designed for post quantum cryptography:

- CRYSTALS-Kyber (key exchange)
- CRYSTALS-Dilithium (signature)
- FALCON (signature)
- SPHINCS+ (signature)
- FrodoKEM (key exchange)
- NTRUEncrypt (key exchange)
- Streamlined NTRU Prime (key exchange)
- BIKE (key exchange)
- HQC (key exchange)
- Picnic (signature)

Normally you want to use them in hybrid mode and use classical algorithms of 
the `wan24-Crypto` package as counter algorithm. To do this per default:

```cs
// Enable the post quantum algorithms as (counter-)defaults
CryptoHelper.ForcePostQuantumSafety();
```

This will use these algorithms as (counter) algorithms for asymmetric 
cryptography, in case you didn't define other post quantum algorithms already:

- NTRUEncrypt (key exchange)
- CRYSTALS-Dilithium (signature)

The counter algorithm will come in effect, if you use asymmetric keys for 
encryption:

```cs
// Create options having a counter private key
CryptoOptions options = EncryptionHelper.GetDefaultOptions();
options.SetCounterPrivateKey(yourNtruPrivateKey);

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

| Algorithm | Parameters |
| --------- | ---------- |
| CRYSTALS-Kyber, CRYSTALS-Dilithium | non-AES |
| SPHINCS+ | Haraka simple* |
| FrodoKEM | AES* |
| Picnic | Full |

**NOTE**: CRYSTALS-Kyber and CRYSTALS-Dilithium AES parameters and SPHINCS+ 
robust parameters are deprecated! SPHINCS+ Haraka parameters are removed from 
the FIPS standard, so `wan24-Crypto-BC` will switch to Shake parameters 
instead. Also the FrodoKEM Shake parameters will be used in the next major 
release, which will require to renew existing keys, which use the AES 
parameters from the current version of this library.

**WARNING** The PQC standards are in development at the moment, so future 
incompatible changes are very likely and will be handled in a new major 
release of this library.

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

| Stream cipher | RNG |
| ------------- | --- |
| ChaCha20 | `ChaCha20Rng` |
| XSalsa20 | `XSalsa20Rng` |

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

## X/Ed448-Goldilocks and X/Ed25519

Just a short note on Curve448: Private and public keys have a different key 
size: The private key has 456 bit, while the public key has 448 bit. Both key 
sizes are supported for key generation and result in the same key sizes for 
the private (456 bit) and the public (448 bit) key. The private key of a key 
pair will always identify with 456 bit, while the public key will always 
identify with 448 bit - no matter which key size was chosen for key pair 
generation.

The Ed448 signature is context based, but currently only an empty byte array 
is being used as context data. Instead of a context you should use the purpose 
free text, which can be given to the signature methods of `wan24-Crypto`.

XEd25519 and XEd448 convert the private Ed25519/448 key to X25519/448 for key 
exchange. The private key stores only the Ed25519/448 information, while the 
public key stores both, the Ed25519/448 and the X25519/448 informations (and 
therefor require a custom serialization format). You can derive Ed25519/448 
private keys from a XEd25519/448 private key, and XEd25519/448 private keys 
from a Ed25519/448 private key.

Using the `ToX25519/448PrivateKey` extension methods for the 
`Ed25519/448PrivateKeyParameters` a conversion to X25519/448 is possible now 
(if you want to use the Bouncy Castle API directly).

**WARNING**: Different Ed25519/448 keys may convert to equal X25519/448 keys, 
so be aware of possible collisions!
