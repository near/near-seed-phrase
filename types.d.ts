declare module 'near-seed-phrase' {
    interface Seed {
        seedPhrase: string;
        secretKey: string;
        publicKey: string;
        keyPair: {
            publicKey: Uint8Array;
            secretKey: Uint8Array;
        }
    }

    export const KEY_DERIVATION_PATH: string;
    export function generateSeedPhrase(entropy?: Buffer): Seed;
    export function normalizeSeedPhrase(seedPhrase: string): string;
    export function parseSeedPhrase(seedPhrase: string, derivationPath?: string): Seed;
    export function findSeedPhraseKey(seedPhrase: string, publicKeys: string[]): Seed|{};
}
