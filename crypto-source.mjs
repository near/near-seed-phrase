// Reproducibly bundled for the existing synchronous CommonJS/browser APIs.
// Only expose seeded key generation; signing remains the SDK's responsibility.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export const keygen = seed => ml_dsa65.keygen(seed);
