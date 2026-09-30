const bip39 = require('bip39-light');
const { derivePath } = require('near-hd-key');
const bs58 = require('bs58');
const nacl = require('tweetnacl');
const { deriveMLDSA65Node, validateMLDSA65Path } = require('./nep649');

const KEY_DERIVATION_PATH = "m/44'/397'/0'"
const FULL_KEY_DERIVATION_PATH = "m/44'/397'/0'/0'/1'"

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
        { keyType: 'ed25519', derivationPath: pathOrOptions || KEY_DERIVATION_PATH } : parseOptions(pathOrOptions)
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
    const seed = usesOptions ?
        bip39.mnemonicToSeed(normalized.normalize('NFKD'), (passphrase || '').normalize('NFKD')) :
        bip39.mnemonicToSeed(normalized)
    if (keyType === 'ml-dsa-65') {
        if (typeof Object.hasOwn !== 'function') {
            throw new Error('ML-DSA-65 requires Node.js 16.9+ or a browser with Object.hasOwn support')
        }
        const { keygen } = require('./mldsa65.cjs')
        const { key } = deriveMLDSA65Node(seed, derivationPath)
        const keyPair = keygen(key)
        return {
            seedPhrase,
            secretKey: 'ml-dsa-65:' + bs58.encode(Buffer.from(keyPair.secretKey)),
            publicKey: 'ml-dsa-65:' + bs58.encode(Buffer.from(keyPair.publicKey))
        }
    }
    const { key } = derivePath(derivationPath, seed.toString('hex'))
    const keyPair = nacl.sign.keyPair.fromSeed(key)
    const publicKey = 'ed25519:' + bs58.encode(Buffer.from(keyPair.publicKey))
    const secretKey = 'ed25519:' + bs58.encode(Buffer.from(keyPair.secretKey))
    return { seedPhrase, secretKey, publicKey }
}

// Return candidates for wallet recovery; no network/account discovery is done.
const deriveSeedPhraseKeys = (seedPhrase, options) => {
    if (options !== undefined && (!options || typeof options !== 'object' || Array.isArray(options))) {
        throw new TypeError('Recovery options must be an object')
    }
    const passphrase = options && options.passphrase
    if (!bip39.validateMnemonic(normalizeSeedPhrase(seedPhrase.normalize('NFKD')))) throw new Error('Invalid BIP-39 mnemonic')
    return ['ed25519', 'ml-dsa-65'].reduce((keys, keyType) => keys.concat(
        [KEY_DERIVATION_PATH, FULL_KEY_DERIVATION_PATH].map(derivationPath => ({
            ...parseSeedPhrase(seedPhrase, { keyType, derivationPath, passphrase }),
            keyType,
            derivationPath
        }))
    ), [])
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
    FULL_KEY_DERIVATION_PATH,
    generateSeedPhrase,
    normalizeSeedPhrase,
    parseSeedPhrase,
    deriveSeedPhraseKeys,
    findSeedPhraseKey
}
