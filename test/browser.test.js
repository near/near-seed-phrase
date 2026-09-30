const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const { webcrypto, createHash } = require('crypto');
const { TextEncoder, TextDecoder } = require('util');
const bs58 = require('bs58');
const { vectors } = require('./nep649-vectors.json');

describe('browser distributions', function () {
    this.timeout(10000);
    for (const filename of ['near-seed-phrase.js', 'near-seed-phrase.min.js']) {
        it(`${filename}: legacy, canonical ML-DSA-65, and secure generation`, () => {
            const context = { window: { crypto: webcrypto }, crypto: webcrypto, TextEncoder, TextDecoder };
            vm.createContext(context);
            vm.runInContext(fs.readFileSync(require.resolve('../dist/' + filename), 'utf8'), context);
            const api = context.window.nearSeedPhrase;
            const legacy = api.parseSeedPhrase('Shoot island position soft burden budget tooth cruel issue economy destroy Above');
            assert.equal(legacy.publicKey, 'ed25519:r4yuiZE45mzeZAENDEF2pWeFBJkW8mQYGx3rU46zCqh');
            const vector = vectors[2];
            const expected = vector.derivations[vector.derivations.length - 1];
            const keys = api.parseSeedPhrase(vector.mnemonic, { keyType: 'ml-dsa-65' });
            for (const [field, digest] of [['secretKey', expected.private_key_sha256], ['publicKey', expected.public_key_sha256]]) {
                assert.equal(createHash('sha256').update(bs58.decode(keys[field].split(':')[1])).digest('hex'), digest);
            }
            const generated = api.generateSeedPhrase(undefined, { keyType: 'ml-dsa-65' });
            assert.equal(generated.seedPhrase.split(' ').length, 24);
            assert.equal(api.parseSeedPhrase(generated.seedPhrase, { keyType: 'ml-dsa-65' }).secretKey, generated.secretKey);
            assert.equal(api.deriveSeedPhraseKeys(vector.mnemonic).length, 4);
        });
        it(`${filename}: recovery needs no RNG and generation fails closed`, () => {
            const context = { window: {}, TextEncoder, TextDecoder };
            vm.createContext(context);
            vm.runInContext(fs.readFileSync(require.resolve('../dist/' + filename), 'utf8'), context);
            const api = context.window.nearSeedPhrase;
            assert.equal(api.parseSeedPhrase(vectors[2].mnemonic, { keyType: 'ml-dsa-65' }).publicKey.startsWith('ml-dsa-65:'), true);
            assert.throws(() => api.generateSeedPhrase(undefined, { keyType: 'ml-dsa-65' }));
        });
    }
});
