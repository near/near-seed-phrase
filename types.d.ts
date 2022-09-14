declare module 'near-seed-phrase' {
    interface Seed {
        seedPhrase: string;
        secretKey: string;
        publicKey: string;
    }

    export function parseSeedPhrase(phrase: string): Seed;
    export function generateSeedPhrase(): Seed;
}
