const assert = require('assert');
const { createHash, createHmac, pbkdf2Sync } = require('crypto');
const bip39 = require('bip39-light');
const bs58 = require('bs58');
const { keygen } = require('../mldsa65.cjs');
const { deriveMLDSA65Node } = require('../nep649');
const { vectors } = require('./nep649-vectors.json');
const {
    parseSeedPhrase, generateSeedPhrase, KEY_DERIVATION_PATH
} = require('../');

const mnemonic = vectors[2].mnemonic;
const pq = { keyType: 'ml-dsa-65' };
const FULL_KEY_DERIVATION_PATH = "m/44'/397'/0'/0'/1'";
const decode = key => bs58.decode(key.split(':')[1]);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

describe('NEP-649 canonical vectors', () => {
    // Digests are taken from the complete upstream key bytes, not this implementation.
    for (const vector of vectors) {
        for (const expected of vector.derivations) {
            it(`${vector.name}: ${expected.path}`, () => {
                const node = deriveMLDSA65Node(Buffer.from(vector.seed, 'hex'), expected.path);
                assert.equal(node.key.toString('hex'), expected.node_secret);
                assert.equal(node.chainCode.toString('hex'), expected.chain_code);
                const pair = keygen(node.key);
                assert.equal(pair.secretKey.length, 4032);
                assert.equal(pair.publicKey.length, 1952);
                assert.equal(hash(pair.secretKey), expected.private_key_sha256);
                assert.equal(hash(pair.publicKey), expected.public_key_sha256);
            });
        }
        if (vector.mnemonic) {
            it(`${vector.name}: mnemonic to NEAR keys`, () => {
                const seed = pbkdf2Sync(vector.mnemonic, 'mnemonic', 2048, 64, 'sha512');
                assert.equal(seed.toString('hex'), vector.seed);
                const keys = parseSeedPhrase(vector.mnemonic, { ...pq, derivationPath: vector.full_derivation_path });
                const expected = vector.derivations[vector.derivations.length - 1];
                assert.equal(hash(decode(keys.secretKey)), expected.private_key_sha256);
                assert.equal(hash(decode(keys.publicKey)), expected.public_key_sha256);
            });
        }
    }
});

describe('NEP-649 seed phrase API', () => {
    it('preserves the legacy Ed25519 defaults and positional paths', () => {
        const legacy = parseSeedPhrase(mnemonic);
        assert.deepStrictEqual(parseSeedPhrase(mnemonic, KEY_DERIVATION_PATH), legacy);
        for (const path of ['', null, false, 0, NaN]) {
            assert.deepStrictEqual(parseSeedPhrase(mnemonic, path), legacy);
        }
        assert.deepStrictEqual(parseSeedPhrase(mnemonic, { keyType: 'ed25519' }), legacy);
        assert.deepStrictEqual(parseSeedPhrase(mnemonic, FULL_KEY_DERIVATION_PATH),
            parseSeedPhrase(mnemonic, { derivationPath: FULL_KEY_DERIVATION_PATH }));
        assert.equal(generateSeedPhrase().seedPhrase.split(' ').length, 12);
        // Existing recovery accepts phrases without checksum validation.
        assert.equal(parseSeedPhrase('not a mnemonic').publicKey.startsWith('ed25519:'), true);
    });

    it('normalizes mnemonic whitespace/case and preserves the supplied phrase', () => {
        const input = '  ' + mnemonic.toUpperCase().replace(/ /g, '\n  ') + '  ';
        const actual = parseSeedPhrase(input, pq);
        assert.equal(actual.seedPhrase, input);
        assert.equal(actual.secretKey, parseSeedPhrase(mnemonic, pq).secretKey);
    });

    it('NFKD-normalizes before validating the mnemonic in new APIs', () => {
        const wide = mnemonic.replace(/[a-z]/g, letter => String.fromCharCode(letter.charCodeAt(0) + 0xfee0));
        assert.equal(parseSeedPhrase(wide, pq).secretKey, parseSeedPhrase(mnemonic, pq).secretKey);
        assert.equal(parseSeedPhrase(wide, pq).seedPhrase, wide);
    });

    it('uses BIP-39 NFKD passphrases without trimming or lowercasing them', () => {
        const passphrase = '  TRÉZOR  ';
        const actual = parseSeedPhrase(mnemonic, { ...pq, passphrase });
        const seed = pbkdf2Sync(mnemonic.normalize('NFKD'), 'mnemonic' + passphrase.normalize('NFKD'), 2048, 64, 'sha512');
        let node = createHmac('sha512', 'ML-DSA-65 seed').update(seed).digest();
        for (const index of [44, 397, 0]) {
            const indexBytes = Buffer.alloc(4);
            indexBytes.writeUInt32BE(index + 0x80000000);
            node = createHmac('sha512', node.slice(32))
                .update(Buffer.concat([Buffer.from([0]), node.slice(0, 32), indexBytes])).digest();
        }
        assert.equal(hash(decode(actual.publicKey)), hash(keygen(node.slice(0, 32)).publicKey));
        assert.equal(actual.secretKey, parseSeedPhrase(mnemonic, { ...pq, passphrase: passphrase.normalize('NFKD') }).secretKey);
        assert.notEqual(actual.secretKey, parseSeedPhrase(mnemonic, pq).secretKey);
        assert.notEqual(actual.secretKey, parseSeedPhrase(mnemonic, { ...pq, passphrase: passphrase.trim() }).secretKey);
    });

    for (const bytes of [16, 20, 24, 28, 32]) {
        it(`recovers a valid ${bytes * 3 / 4}-word mnemonic`, () => {
            const phrase = bip39.entropyToMnemonic(Buffer.alloc(bytes));
            const keys = parseSeedPhrase(phrase, pq);
            assert.equal(decode(keys.secretKey).length, 4032);
        });
    }

    it('generates 24 words by default for ML-DSA-65', () => {
        const result = generateSeedPhrase(undefined, pq);
        assert.equal(result.seedPhrase.split(' ').length, 24);
        assert.deepStrictEqual(parseSeedPhrase(result.seedPhrase, pq), result);
    });

    for (const bytes of [24, 28, 32]) {
        it(`generates ${bytes * 3 / 4} words from supplied entropy`, () => {
            const options = { ...pq, passphrase: 'test', derivationPath: FULL_KEY_DERIVATION_PATH };
            const result = generateSeedPhrase(Buffer.alloc(bytes), options);
            assert.equal(result.seedPhrase.split(' ').length, bytes * 3 / 4);
            assert.deepStrictEqual(parseSeedPhrase(result.seedPhrase, options), result);
            assert.deepStrictEqual(generateSeedPhrase('00'.repeat(bytes), options), result);
        });
    }

    it('supports both default paths in both derivation trees', () => {
        const keys = ['ed25519', 'ml-dsa-65'].flatMap(keyType =>
            [KEY_DERIVATION_PATH, FULL_KEY_DERIVATION_PATH].map(derivationPath =>
                parseSeedPhrase(mnemonic, { keyType, derivationPath }).publicKey));
        assert.equal(new Set(keys).size, 4);
    });

    for (const path of ["m/44'/397'/2147483647'", "m/44'/397'/0'/0'/1'/2'"]) {
        it(`supports valid hardened boundary/deeper path ${path}`, () => {
            assert.equal(decode(parseSeedPhrase(mnemonic, { ...pq, derivationPath: path }).secretKey).length, 4032);
        });
    }

    for (const path of ['', 'm', "m/44'/0'/0'", "m/44'/397'/0'/0'", "m/44'/397'/0'/0/1'",
        "m/44'/397'/2147483648'", "m/44'/397'/999999999999999999999'", "m/44'/397'/-1'",
        "m/44'/397'/1.5'", "m/44'/397'/01'", "m/44'/397'/0' ", "m/44'/397'/0'/", "m/44'/397'/0h"]) {
        it(`rejects invalid wallet path ${JSON.stringify(path)}`, () => {
            assert.throws(() => parseSeedPhrase(mnemonic, { ...pq, derivationPath: path }));
        });
    }

    it('rejects invalid inputs instead of falling back to another key', () => {
        for (const phrase of ['', 'not a mnemonic', 'abandon '.repeat(12).trim()]) {
            assert.throws(() => parseSeedPhrase(phrase, pq), /mnemonic/);
        }
        for (const options of [null, [], 'ml-dsa-65', { keyType: 'secp256k1' }, { passphrase: 12 }, { derivationPath: 1 }]) {
            assert.throws(() => generateSeedPhrase(undefined, options));
        }
        for (const entropy of [Buffer.alloc(16), Buffer.alloc(20), '00'.repeat(16), 'gg'.repeat(24), '00'.repeat(33)]) {
            assert.throws(() => generateSeedPhrase(entropy, pq), /entropy/);
        }
        for (const bytes of [0, 15, 65]) assert.throws(() => deriveMLDSA65Node(Buffer.alloc(bytes), 'm'));
        assert.throws(() => deriveMLDSA65Node(Buffer.alloc(64), 'm/0'));
    });
});
