declare module 'near-seed-phrase' {
    export interface Seed {
        seedPhrase: string;
        secretKey: string;
        publicKey: string;
    }

    export interface SeedPhraseOptions {
        keyType?: 'ed25519' | 'ml-dsa-65';
        derivationPath?: string;
        passphrase?: string;
    }

    export const KEY_DERIVATION_PATH: string;
    export function generateSeedPhrase(entropy?: Buffer | string, options?: SeedPhraseOptions): Seed;
    export function normalizeSeedPhrase(seedPhrase: string): string;
    export function parseSeedPhrase(seedPhrase: string, derivationPath?: string | SeedPhraseOptions): Seed;
    export function findSeedPhraseKey(seedPhrase: string, publicKeys: string[]): Seed|{};
}
