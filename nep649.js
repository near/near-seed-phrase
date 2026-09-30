const { createHmac } = require('crypto');

const HARDENED_OFFSET = 0x80000000;

// Internal SLIP-0010 primitive. Wallet-facing paths are checked separately.
const deriveMLDSA65Node = (seed, path) => {
    if (!Buffer.isBuffer(seed) || seed.length < 16 || seed.length > 64) {
        throw new TypeError('Seed must contain 16 to 64 bytes');
    }
    if (typeof path !== 'string' || !/^m(?:\/(?:0|[1-9][0-9]*)')*$/.test(path)) {
        throw new Error('ML-DSA-65 derivation paths must be hardened');
    }
    const indices = path.split('/').slice(1).map(part => Number(part.slice(0, -1)));
    if (indices.some(index => !Number.isSafeInteger(index) || index >= HARDENED_OFFSET)) {
        throw new RangeError('Derivation indices must be between 0 and 2147483647');
    }

    // The NEP-649 reference implementation and vectors use this exact string.
    let node = createHmac('sha512', 'ML-DSA-65 seed').update(seed).digest();
    for (const index of indices) {
        const data = Buffer.alloc(37);
        node.copy(data, 1, 0, 32);
        data.writeUInt32BE(index + HARDENED_OFFSET, 33);
        node = createHmac('sha512', node.slice(32)).update(data).digest();
    }
    return { key: node.slice(0, 32), chainCode: node.slice(32) };
};

const validateMLDSA65Path = path => {
    const parts = typeof path === 'string' ? path.split('/') : [];
    if (parts[0] !== 'm' || parts[1] !== "44'" || parts[2] !== "397'" ||
        (parts.length !== 4 && parts.length < 6)) {
        throw new Error("ML-DSA-65 paths must use m/44'/397'/account' or a full hardened NEAR path");
    }
};

module.exports = { deriveMLDSA65Node, validateMLDSA65Path };
