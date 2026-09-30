# NEAR Seed Phrase

Create and recover NEAR keys from English BIP-39 seed phrases.

### Install

```sh
npm i near-seed-phrase
```

### Usage

```js
const { parseSeedPhrase, generateSeedPhrase } = require('near-seed-phrase');

// Existing calls still use Ed25519 and generate 12-word phrases.
const { seedPhrase, publicKey, secretKey } = generateSeedPhrase();
const recovered = parseSeedPhrase(seedPhrase);

// Opt into NEP-649 ML-DSA-65 derivation; new phrases default to 24 words.
const options = { keyType: 'ml-dsa-65', derivationPath: "m/44'/397'/0'" };
const pq = generateSeedPhrase(undefined, options);
const recoveredPQ = parseSeedPhrase(pq.seedPhrase, options);
```

`parseSeedPhrase(phrase, options)` accepts `keyType` (`ed25519` by default),
`derivationPath`, and an optional BIP-39 `passphrase`. The original positional
`parseSeedPhrase(phrase, path)` remains supported for Ed25519. Passphrases are
case-sensitive and NFKD-normalized, never trimmed; changing one changes the
key. Keep recovery settings securely with your backup.

The default path is `m/44'/397'/0'`. ML-DSA-65 supports NEAR's short
`m/44'/397'/account'` and full `m/44'/397'/account'/change'/index'` hardened
paths. Each index must be below 2147483648. Wallet recovery should check both
`m/44'/397'/0'` and `m/44'/397'/0'/0'/1'` in both key trees using
`parseSeedPhrase`; network discovery is the wallet's responsibility.
`findSeedPhraseKey` keeps its original short-path Ed25519 behavior.

Recovery accepts valid 12–24-word phrases. New ML-DSA-65 phrases require at
least 18 words: supplied entropy must be 24, 28, or 32 bytes (Buffer or hex).
Shorter recovered phrases retain their original entropy limit. Returned
`ml-dsa-65:` strings contain the full 1952-byte public key and expanded
4032-byte secret key, not the derivation seed. Never share secret material.

The implementation follows the [NEP-649 draft and reference vectors](https://github.com/vsavchyn-dev/NEPs/blob/cecbad372435edd17607a0a45401ab2cf5839fc8/neps/nep-0649.md),
using the reference's exact `ML-DSA-65 seed` domain string.

### Development

The supported noble 0.7.1 key generator is bundled into a synchronous
CommonJS adapter to preserve older Node compatibility. Ed25519 keeps its
existing runtime support; ML-DSA-65 needs Node 16.9+. Rebuilding requires
Node 20.19+ and regenerates the adapter and browser bundles together.
When updating noble, rebuild and retain the third-party license notices.

Run `yarn test` and `yarn dist`. Tests cover all canonical vectors, existing
Ed25519 keys, input boundaries, and both browser bundles. Browser bundles
expose `window.nearSeedPhrase` and require a modern browser with Web Crypto.
