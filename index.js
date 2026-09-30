const bip39 = require('bip39-light');
const { derivePath } = require('near-hd-key');
const bs58 = require('bs58');
const nacl = require('tweetnacl');
const { deriveMLDSA65Node, validateMLDSA65Path } = require('./nep649');

const KEY_DERIVATION_PATH = "m/44'/397'/0'"

const parseOptions = (options) => {
    if (options === undefined) return { keyType: 'ed25519' }
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
        throw new TypeError('Seed phrase options must be an object')
    }
    const { keyType = 'ed25519', derivationPath, passphrase } = options
    if (keyType !== 'ed25519' && keyType !== 'ml-dsa-65') {
        throw new Error('Unsupported key type: ' + keyType)
    }
    if (derivationPath !== undefined && typeof derivationPath !== 'string') {
        throw new TypeError('Derivation path must be a string')
    }
    if (passphrase !== undefined && typeof passphrase !== 'string') {
        throw new TypeError('Passphrase must be a string')
    }
    return { keyType, derivationPath, passphrase }
}

const generateSeedPhrase = (entropy, options) => {
    const parsed = parseOptions(options)
    if (parsed.keyType === 'ml-dsa-65' && entropy !== undefined) {
        const hex = Buffer.isBuffer(entropy) ? entropy.toString('hex') : entropy
        if (typeof hex !== 'string' || !/^(?:[0-9a-fA-F]{48}|[0-9a-fA-F]{56}|[0-9a-fA-F]{64})$/.test(hex)) {
            throw new Error('New ML-DSA-65 mnemonics require 192, 224, or 256 bits of entropy')
        }
    }
    const seedPhrase = entropy !== undefined ? bip39.entropyToMnemonic(entropy) :
        bip39.generateMnemonic(parsed.keyType === 'ml-dsa-65' ? 256 : 128)
    return parseSeedPhrase(seedPhrase, options)
}

const normalizeSeedPhrase = (seedPhrase) => seedPhrase.trim().split(/\s+/).map(part => part.toLowerCase()).join(' ')

const parseSeedPhrase = (seedPhrase, pathOrOptions) => {
    // Preserve the original positional path API, including its legacy defaults.
    const options = typeof pathOrOptions === 'string' ?
        { keyType: 'ed25519', derivationPath: pathOrOptions || KEY_DERIVATION_PATH } : parseOptions(pathOrOptions || undefined)
    const { keyType, passphrase } = options
    const derivationPath = options.derivationPath === undefined ? KEY_DERIVATION_PATH : options.derivationPath
    const usesOptions = pathOrOptions && typeof pathOrOptions === 'object'
    const normalized = normalizeSeedPhrase(usesOptions ? seedPhrase.normalize('NFKD') : seedPhrase)
    if (keyType === 'ml-dsa-65') {
        if (!bip39.validateMnemonic(normalized)) throw new Error('Invalid BIP-39 mnemonic')
        validateMLDSA65Path(derivationPath)
    }
    // bip39-light predates normalization support. Apply BIP-39's NFKD rule
    // only for the new options API; legacy recovery must remain byte-identical.
    const seed = bip39.mnemonicToSeed(usesOptions ? normalized.normalize('NFKD') : normalized,
        passphrase === undefined ? '' : passphrase.normalize('NFKD'))
    const { key } = keyType === 'ml-dsa-65' ?
        deriveMLDSA65Node(seed, derivationPath) : derivePath(derivationPath, seed.toString('hex'))
    if (keyType === 'ml-dsa-65' && typeof Object.hasOwn !== 'function') {
        throw new Error('ML-DSA-65 requires Node.js 16.9+ or a browser with Object.hasOwn support')
    }
    const keyPair = keyType === 'ml-dsa-65' ? require('./mldsa65.cjs').keygen(key) : nacl.sign.keyPair.fromSeed(key)
    const publicKey = keyType + ':' + bs58.encode(Buffer.from(keyPair.publicKey))
    const secretKey = keyType + ':' + bs58.encode(Buffer.from(keyPair.secretKey))
    return { seedPhrase, secretKey, publicKey }
}

const findSeedPhraseKey = (seedPhrase, publicKeys) => {
    // TODO: Need to iterate through multiple possible derivation paths?
    const keyInfo = parseSeedPhrase(seedPhrase)
    if (publicKeys.indexOf(keyInfo.publicKey) < 0) {
        return {}
    }
    return keyInfo
}

module.exports = {
    KEY_DERIVATION_PATH,
    generateSeedPhrase,
    normalizeSeedPhrase,
    parseSeedPhrase,
    findSeedPhraseKey
}
