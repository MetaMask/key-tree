import { getPublicKey as getEd25519PublicKey } from '@noble/ed25519';

export { CURVE as curve } from '@noble/ed25519';

export const name = 'ed25519';
export const secret = Buffer.from('ed25519 seed', 'utf8');

// All private keys are valid for ed25519
export const isValidPrivateKey = () => true;

export const getPublicKey = async (
  privateKey: Uint8Array | string | bigint,
  _compressed?: boolean,
): Promise<Buffer> => {
  const publicKey = await getEd25519PublicKey(privateKey);
  return Buffer.concat([Buffer.alloc(1, 0), publicKey]);
};
