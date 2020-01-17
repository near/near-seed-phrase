const assert = require('assert');
const { generateSeedPhrase, normalizeSeedPhrase, parseSeedPhrase, findSeedPhraseKey } = require('../');

describe('seed phrase', () => {
    it('normalize', async() => {
        assert.equal(normalizeSeedPhrase(' Almost a Seed    Phrase'), 'almost a seed phrase');
    });
});