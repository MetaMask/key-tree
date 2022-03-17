import { utils, getPublicKey as getSecp256k1PublicKey } from '@noble/secp256k1';

export { CURVE as curve } from '@noble/secp256k1';
export const { isValidPrivateKey } = utils;

export const name = 'secp256k1';
export const secret = Buffer.from('Bitcoin seed', 'utf8');

export const getPublicKey = (
  privateKey: Uint8Array | string | bigint,
  compressed?: boolean,
): Buffer => Buffer.from(getSecp256k1PublicKey(privateKey, compressed));
