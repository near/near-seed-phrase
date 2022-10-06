const assert = require('assert');
const nacl = require('tweetnacl');
const {
    generateSeedPhrase,
    normalizeSeedPhrase,
    parseSeedPhrase,
    findSeedPhraseKey
} = require('../');

describe('seed phrase', () => {
    it('generate', () => {
        const { seedPhrase, secretKey, publicKey, keyPair } = generateSeedPhrase();
        assert.ok(seedPhrase);
        assert.ok(secretKey);
        assert.ok(publicKey);
        assert.ok(keyPair);
    });

    it('generate with entropy', () => {
        const entropy = Buffer.from(nacl.hash(Buffer.from('The quick brown fox jumps over the lazy dog', 'utf8'))).toString('hex')
        const { seedPhrase, secretKey } = generateSeedPhrase(entropy.substr(0, 32));
        const { secretKey: secretKey2 } = parseSeedPhrase(seedPhrase);
        assert.strictEqual(secretKey, secretKey2);
    });

    it('normalize', () => {
        assert.equal(normalizeSeedPhrase(' Almost a Seed    Phrase'), 'almost a seed phrase');
    });

    it('parse seed phrase', () => {
        const { secretKey, publicKey, keyPair } = parseSeedPhrase('Shoot island position soft burden budget tooth cruel issue economy destroy Above')

        assert.equal(secretKey, 'ed25519:3jFpZEcbhcjpqVE27zU3d7WHcS7Wq716v5WryU8Tj4EaNTHTj8iAhtPW7KCdFV2fnjNf9toawUbdqZnhrRtLKe6w');
        assert.equal(publicKey, 'ed25519:r4yuiZE45mzeZAENDEF2pWeFBJkW8mQYGx3rU46zCqh');
        assert.deepEqual(keyPair, {
            publicKey: new Uint8Array([
                12, 145, 246, 16, 111, 248, 53, 192,
                25, 93, 83, 136, 86, 90, 45, 105,
                226, 80, 56, 167, 226, 61, 38, 25,
                143, 133, 202, 246, 89, 65, 23, 236
            ]),
            secretKey: new Uint8Array([
                136, 121, 58, 142, 238, 197, 55, 198, 126, 232, 212,
                89, 241, 137, 154, 71, 162, 241, 183, 82, 208, 106,
                76, 121, 60, 102, 253, 117, 29, 248, 4, 152, 12,
                145, 246, 16, 111, 248, 53, 192, 25, 93, 83, 136,
                86, 90, 45, 105, 226, 80, 56, 167, 226, 61, 38,
                25, 143, 133, 202, 246, 89, 65, 23, 236
            ]),
        })
    });

    it('find matching public key', () => {
        const { seedPhrase, secretKey, publicKey, keyPair } = generateSeedPhrase();

        const keyInfo = findSeedPhraseKey(seedPhrase, ["whatever", publicKey, "something"]);
        assert.deepStrictEqual(keyInfo, { seedPhrase, secretKey, publicKey, keyPair });
    });

    it('find matching public key (not found)', () => {
        const { seedPhrase } = generateSeedPhrase();

        const keyInfo = findSeedPhraseKey(seedPhrase, ["whatever", "something"]);
        assert.deepStrictEqual(keyInfo, {});
    });
});
