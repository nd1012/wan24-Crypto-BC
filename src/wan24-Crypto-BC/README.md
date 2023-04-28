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

**CAUTION**: The underlaying Bouncy Castle library is 
[forked](https://github.com/nd1012/bc-csharp) from its original GitHub 
repository, and it's using the main branch. The main branch is not yet 
released! So this library should be seen as experimental and not being used in 
a productive environment! The Bouncy Castle build will be updated from time to 
time. As soon as the official NuGet package has PQC support, this library will 
switch to the NuGet package.

## How to get it

This library is available as 
[NuGet package](https://www.nuget.org/packages/wan24-Crypto-BC/).

## Usage

In case you don't use the `wan24-Core` bootstrapper logic, you need to 
initialize the Bouncy Castle extension first, before you can use it:

```cs
wan24.Crypo.BC.Bootstrapper.Boot();
```

This will register the algorithms to the `wan24-Crypto` library.

## Post quantum safety

These algorithms are designed for post quantum cryptography:

- CRYSTALS-Kyber (key exchange)
- CRYSTALS-Dilithium (signature)
- FALCON (signature)
- SPHINCS+ (signature)

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

For using FALCON or SPHINCS+ for signature instead:

```cs
// FALCON
HybridAlgorithmHelper.SignatureAlgorithm = 
    AsymmetricHelper.GetAlgorithm(AsymmetricFalconAlgorithm.ALGORITHM_NAME);

// SPHINCS+
HybridAlgorithmHelper.SignatureAlgorithm = 
    AsymmetricHelper.GetAlgorithm(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME);
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
When using SPHINCS+, the Haraka F hashing parameters will be used.
