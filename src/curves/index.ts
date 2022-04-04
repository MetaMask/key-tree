import * as secp256k1 from './secp256k1';
import * as ed25519 from './ed25519';

export * from './curve';
export * as secp256k1 from './secp256k1';
export * as ed25519 from './ed25519';

export const curves = {
  secp256k1,
  ed25519,
};
