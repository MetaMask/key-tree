import { mnemonicToEntropy } from '@metamask/scure-bip39';
import { wordlist as englishWordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import { assert, stringToBytes } from '@metamask/utils';

import type { DeriveChildKeyArgs } from '.';
import type { BIP39StringNode } from '../constants';
import { BYTES_KEY_LENGTH } from '../constants';
import { hmacSha512, pbkdf2Sha512 } from '../cryptography';
import type { Curve } from '../curves';
import { SLIP10Node } from '../SLIP10Node';
import { getFingerprint } from '../utils';

/**
 * Encode a BIP-39 mnemonic phrase to a `Uint8Array` for use in seed generation.
 * If the mnemonic is already a `Uint8Array`, it is assumed to contain the
 * indices of the words in the wordlist.
 *
 * @param mnemonic - The mnemonic phrase to encode.
 * @param wordlist - The wordlist to use.
 * @returns The encoded mnemonic phrase.
 */
function encodeMnemonicPhrase(
  mnemonic: string | Uint8Array,
  wordlist: string[],
) {
  if (typeof mnemonic === 'string') {
    return stringToBytes(mnemonic.normalize('NFKD'));
  }

  return stringToBytes(
    Array.from(new Uint16Array(mnemonic.buffer))
      .map((i) => wordlist[i])
      .join(' '),
  );
}

/**
 * Convert a BIP-39 mnemonic phrase to a seed.
 *
 * @param mnemonic - The BIP-39 mnemonic phrase to convert. If the mnemonic is a
 * `Uint8Array`, it is assumed to contain the indices of the words in the
 * English wordlist.
 * @param passphrase - The passphrase to use.
 */
export async function mnemonicToSeed(
  mnemonic: string | Uint8Array,
  passphrase = '',
) {
  return await pbkdf2Sha512(
    encodeMnemonicPhrase(mnemonic, englishWordlist),
    stringToBytes(`mnemonic${passphrase}`.normalize('NFKD')),
    2048,
    64,
  );
}

/**
 * Convert a BIP-39 mnemonic phrase to a multi path.
 *
 * @param mnemonic - The BIP-39 mnemonic phrase to convert.
 * @returns The multi path.
 */
export function bip39MnemonicToMultipath(mnemonic: string): BIP39StringNode {
  return `bip39:${mnemonic.toLowerCase().trim()}`;
}

/**
 * Create a {@link SLIP10Node} from a BIP-39 mnemonic phrase.
 *
 * @param options - The options for creating the node.
 * @param options.path - The multi path.
 * @param options.curve - The curve to use for derivation.
 * @returns The node.
 */
export async function deriveChildKey({
  path,
  curve,
}: DeriveChildKeyArgs): Promise<SLIP10Node> {
  switch (curve.masterNodeGenerationSpec) {
    case 'slip10':
      return createBip39KeyFromSeed(await mnemonicToSeed(path), curve);
    case 'cip3':
      return entropyToCip3MasterNode(
        mnemonicToEntropy(path, englishWordlist),
        curve,
      );
    default:
      throw new Error('Unsupported master node generation spec.');
  }
}

/**
 * Create a {@link SLIP10Node} from a BIP-39 seed.
 *
 * @param seed - The cryptographic seed bytes.
 * @param curve - The curve to use.
 * @returns An object containing the corresponding BIP-39 master key and chain
 * code.
 */
export async function createBip39KeyFromSeed(
  seed: Uint8Array,
  curve: Extract<Curve, { masterNodeGenerationSpec: 'slip10' }>,
): Promise<SLIP10Node> {
  assert(
    seed.length >= 16 && seed.length <= 64,
    'Invalid seed: The seed must be between 16 and 64 bytes long.',
  );

  const key = await hmacSha512(curve.secret, seed);
  const privateKey = key.slice(0, BYTES_KEY_LENGTH);
  const chainCode = key.slice(BYTES_KEY_LENGTH);

  assert(
    curve.isValidPrivateKey(privateKey),
    'Invalid private key: The private key must greater than 0 and less than the curve order.',
  );

  const masterFingerprint = getFingerprint(
    await curve.getPublicKey(privateKey, true),
    curve.compressedPublicKeyLength,
  );

  return SLIP10Node.fromExtendedKey({
    privateKey,
    chainCode,
    masterFingerprint,
    depth: 0,
    parentFingerprint: 0,
    index: 0,
    curve: curve.name,
  });
}

/**
 * Create a {@link SLIP10Node} from BIP-39 entropy.
 * This function is consistent with the Icarus derivation scheme.
 * Icarus root key derivation scheme: https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/Icarus.md.
 * CIP3: https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/CIP-0003.md#master-key-generation.
 *
 * @param entropy - The entropy value.
 * @param curve - The curve to use.
 * @returns The root key pair consisting of 64-byte private key and 32-byte chain code.
 */
export async function entropyToCip3MasterNode(
  entropy: Uint8Array,
  curve: Extract<Curve, { masterNodeGenerationSpec: 'cip3' }>,
): Promise<SLIP10Node> {
  assert(
    entropy.length >= 16 && entropy.length <= 64,
    'Invalid entropy: The entropy must be between 16 and 64 bytes long.',
  );

  const rootNode = await pbkdf2Sha512(curve.secret, entropy, 4096, 96);

  // Consistent with the Icarus derivation scheme.
  // https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/Icarus.md
  /* eslint-disable no-bitwise */
  rootNode[0] &= 0b1111_1000;
  rootNode[31] &= 0b0001_1111;
  rootNode[31] |= 0b0100_0000;
  /* eslint-enable no-bitwise */

  const privateKey = rootNode.slice(0, curve.privateKeyLength);
  const chainCode = rootNode.slice(curve.privateKeyLength);

  assert(curve.isValidPrivateKey(privateKey), 'Invalid private key.');

  const masterFingerprint = getFingerprint(
    await curve.getPublicKey(privateKey),
    curve.compressedPublicKeyLength,
  );

  return SLIP10Node.fromExtendedKey({
    privateKey,
    chainCode,
    masterFingerprint,
    depth: 0,
    parentFingerprint: 0,
    index: 0,
    curve: curve.name,
  });
}
