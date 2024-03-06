import {
  stringToBytes,
  bytesToHex,
  hexToBigInt,
  remove0x,
} from '@metamask/utils';
import { mod } from '@noble/curves/abstract/modular';
import { ed25519 } from '@noble/curves/ed25519';

export const curve = ed25519.CURVE;

/**
 * Named after whitepaper: BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace
 * https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf
 * "vanilla" "ed25519" curve follows SLIP10: https://tezos.stackexchange.com/questions/2837/can-i-use-bip32-hd-key-pairs-to-derive-ed25519-addresses
 * note that that the important difference of the "bip32" version is that it allows unhardened key derivation
 */
export const name = 'ed25519Bip32';

// Secret is empty string if not provided by user
export const secret = stringToBytes('');

/**
 * Always returns true.
 * For root node derivation, https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/Icarus.md does not mention any cases when the private key is invalid.
 * For child node derivation, https://input-output-hk.github.io/adrestia/static/Ed25519_BIP.pdf does not mention any cases when the private key is invalid.
 *
 * @param _privateKey - The private key to check.
 * @returns True.
 */
export const isValidPrivateKey = (_privateKey: Uint8Array | string | bigint) =>
  true;

export const deriveUnhardenedKeys = true;

export const publicKeyLength = 32;

const bytesToNumberLE = (bytes: Uint8Array): bigint => {
  return hexToBigInt(bytesToHex(Uint8Array.from(bytes).reverse()));
};

const modN = (a: bigint) => {
  return mod(a, curve.n);
};

// Little-endian SHA512 with modulo n
const modNLE = (hash: Uint8Array): bigint => {
  return modN(bytesToNumberLE(hash));
};

// equivalent to https://github.com/jedisct1/libsodium/blob/93a6e79750a31bc0b946bf483b2ba1c77f9e94ce/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c#L105
// which is used by cardano-js-sdk/crypto https://github.com/input-output-hk/cardano-js-sdk/blob/8a6db2a251cd1c956f52730a0d35de2b7fc67404/packages/crypto/src/Bip32/Bip32PrivateKey.ts#L161
const multiplyWithBase = (key: Uint8Array): Uint8Array => {
  const scalar = modNLE(key); // The actual scalar
  const point = ed25519.ExtendedPoint.BASE.multiply(scalar); // Point on Edwards curve aka public key
  return point.toRawBytes(); // Uint8Array representation
};

export const getPublicKey = async (
  privateKey: Uint8Array,
  _compressed?: boolean,
): Promise<Uint8Array> => {
  return multiplyWithBase(privateKey.slice(0, 32));
};

export const publicAdd = (
  _publicKey: Uint8Array,
  _tweak: Uint8Array,
): Uint8Array => {
  return ed25519.ExtendedPoint.fromHex(remove0x(bytesToHex(_publicKey)))
    .add(ed25519.ExtendedPoint.fromHex(remove0x(bytesToHex(_tweak))))
    .toRawBytes();
};

export const compressPublicKey = (publicKey: Uint8Array): Uint8Array => {
  // Ed25519 public keys don't have a compressed form.
  return publicKey;
};

export const decompressPublicKey = (publicKey: Uint8Array): Uint8Array => {
  // Ed25519 public keys don't have a compressed form.
  return publicKey;
};

export const privateKeyLength = 64;

export const masterNodeGenerationSpec = 'cip3Icarus';
