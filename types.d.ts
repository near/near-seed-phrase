declare module 'near-seed-phrase' {
    interface Seed {
        seedPhrase: string;
        secretKey: string;
        publicKey: string;
    }

    export function parseSeedPhrase(seedPhrase: string, derivationPath: string): Seed;
    export function generateSeedPhrase(): Seed;
}
