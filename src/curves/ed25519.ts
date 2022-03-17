import { getPublicKey as getEd25519PublicKey } from '@noble/ed25519';

export { CURVE as curve } from '@noble/ed25519';

export const secret = Buffer.from('ed25519 seed', 'utf8');

// All private keys are valid for ed25519
export const isValidPrivateKey = () => true;

export const getPublicKey = async (
  privateKey: Uint8Array | string | bigint,
  _compressed?: boolean,
): Promise<Buffer> => Buffer.from(await getEd25519PublicKey(privateKey));
