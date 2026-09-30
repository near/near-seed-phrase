# NEAR Seed Phrase

This tool enables creating and converting mnemonic-phrases, public key and private key for NEAR accounts.

### Install
```js
npm i near-seed-phrase
```

### Usage
```js
const { parseSeedPhrase, generateSeedPhrase } = require('near-seed-phrase');

// to create a seed phrase with its corresponding Keys
const {seedPhrase, publicKey, secretKey} = generateSeedPhrase()

// To recover keys from the seed phrase
const { publicKey, secretKey } = parseSeedPhrase(seedPhrase);
```

### ML-DSA-65 (NEP-649)

ML-DSA-65 is opt-in. Existing calls still derive the same Ed25519 keys and
generate 12-word phrases. The options API also accepts an optional BIP-39
`passphrase` (case-sensitive, normalized to NFKD, never trimmed).

```js
const { generateSeedPhrase, parseSeedPhrase, deriveSeedPhraseKeys } = require('near-seed-phrase');

// New ML-DSA-65 phrases default to 24 words (256 bits of entropy).
const generated = generateSeedPhrase(undefined, { keyType: 'ml-dsa-65' });

// Restore an existing English BIP-39 phrase, including a 12-word phrase.
const keys = parseSeedPhrase(generated.seedPhrase, {
    keyType: 'ml-dsa-65',
    derivationPath: "m/44'/397'/0'", // the default
    passphrase: '' // optional; record this separately if nonempty
});

// Wallet recovery: both default paths in both signature-scheme trees.
const candidates = deriveSeedPhraseKeys(generated.seedPhrase, { passphrase: '' });
// Each candidate contains seedPhrase, publicKey, secretKey, keyType, derivationPath.
```

`parseSeedPhrase(seedPhrase, derivationPath)` remains supported for Ed25519.
The second argument may instead be a `SeedPhraseOptions` object:

- `keyType`: `'ed25519'` (default) or `'ml-dsa-65'`
- `derivationPath`: defaults to `m/44'/397'/0'`; ML-DSA-65 requires every
  component to be hardened and uses NEAR's `44'/397'` prefix
- `passphrase`: optional BIP-39 passphrase; changing it changes the keys

Both short `m/44'/397'/account'` and full
`m/44'/397'/account'/change'/index'` ML-DSA-65 paths are supported. The full
default is `m/44'/397'/0'/0'/1'`, exported as `FULL_KEY_DERIVATION_PATH`.
The two defaults produce different keys. Deeper hardened paths are supported;
retain the exact path with the backup, since other wallets may only check the
two defaults. Indices must be between 0 and 2147483647 before hardening.

`generateSeedPhrase(entropy, options)` accepts a Buffer or hexadecimal entropy
string. New ML-DSA-65 phrases require 24, 28, or 32 bytes of entropy (18, 21,
or 24 words). Recovery accepts all valid English BIP-39 lengths, including 12
and 15 words, but those shorter phrases limit post-quantum security. Use a
cryptographically secure random source when supplying your own entropy.

Returned ML-DSA-65 keys use `ml-dsa-65:<base58>` strings containing the full
1952-byte public key and expanded 4032-byte secret key. The secret is **not**
the 32-byte derivation seed. Never share a mnemonic, passphrase, or secret key.
Derivation is offline and does not add keys, rotate access keys, or discover
accounts on-chain. `deriveSeedPhraseKeys` returns four candidates in order:
short Ed25519, full Ed25519, short ML-DSA-65, full ML-DSA-65. Existing
`findSeedPhraseKey` retains its original short-path Ed25519-only behavior.

This implementation follows the
[NEP-649 draft at cecbad3](https://github.com/vsavchyn-dev/NEPs/blob/cecbad372435edd17607a0a45401ab2cf5839fc8/neps/nep-0649.md)
and its [canonical vectors](https://github.com/vsavchyn-dev/NEPs/blob/cecbad372435edd17607a0a45401ab2cf5839fc8/neps/assets/nep-0649/test-vectors.json).
The proposal is still a draft. Its reference implementation and vectors use
the exact domain string `ML-DSA-65 seed`; one numbered prose step currently
omits ` seed`. The two schemes use separate derivation trees; an Ed25519
private key is never reused as an ML-DSA seed.

### Runtime and browser builds

CommonJS `require` and synchronous APIs are retained. The ML-DSA adapter is
loaded only when ML-DSA keys are requested; the existing Ed25519 path does not
load it. ML-DSA-65 requires Node.js 16.9+ or a modern browser with BigInt,
TextEncoder, and Object.hasOwn support. The adapter targets ES2020 syntax
but also uses Object.hasOwn. The browser bundles expose
`window.nearSeedPhrase`; random generation additionally requires Web Crypto.
Legacy Ed25519-only CommonJS/Node consumers do not acquire the build
dependencies or the adapter's newer runtime requirements. Browser bundles
include the adapter's syntax even when only Ed25519 is used.

The adapter bundles the supported `@noble/post-quantum@0.7.1` and
`@noble/hashes@2.4.0` / `@noble/curves@2.4.0` helpers from the exact build
dependencies in `yarn.lock`.
`crypto-source.mjs` is the small wrapper; `mldsa65.cjs` is its checked-in,
reproducible esbuild output. No ML-DSA algorithm is implemented in this
package. Bundled dependencies will not appear in consumers' production
dependency scans: security updates require updating the pinned build
dependencies and regenerating **both** the adapter and browser bundles.
Third-party license notices are included in `THIRD_PARTY_LICENSES.txt`.
All four upstream vectors, including complete secret/public key digests, are
tested. Developing/rebuilding this package requires Node.js 20.19 or later.

Run `yarn test` for Node tests, `yarn dist` to rebuild both browser bundles,
and `yarn test:browser` to verify the generated bundles against a canonical
vector and the legacy Ed25519 fixture in a browser-like context.
