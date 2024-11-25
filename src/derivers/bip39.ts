import { wordlist as englishWordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import { assert, stringToBytes } from '@metamask/utils';

import type { DeriveChildKeyArgs } from '.';
import type { BIP39StringNode } from '../constants';
import { BYTES_KEY_LENGTH } from '../constants';
import type { CryptographicFunctions } from '../cryptography';
import { sha256, hmacSha512, pbkdf2Sha512 } from '../cryptography';
import type { Curve } from '../curves';
import { SLIP10Node } from '../SLIP10Node';
import { getFingerprint } from '../utils';

const MNEMONIC_PHRASE_LENGTHS = [12, 15, 18, 21, 24];

/**
 * Validate a BIP-39 mnemonic phrase. The phrase must:
 *
 * - Consist of 12, 15, 18, 21, or 24 words.
 * - Contain only words from the English wordlist.
 *
 * @param mnemonicPhrase - The mnemonic phrase to validate.
 * @throws If the mnemonic phrase is invalid.
 */
function validateMnemonicPhrase(mnemonicPhrase: string) {
  const words = mnemonicPhrase.split(' ');

  assert(
    MNEMONIC_PHRASE_LENGTHS.includes(words.length),
    `Invalid mnemonic phrase: The mnemonic phrase must consist of 12, 15, 18, 21, or 24 words.`,
  );

  assert(
    words.every((word) => englishWordlist.includes(word)),
    'Invalid mnemonic phrase: The mnemonic phrase contains an unknown word.',
  );
}

/**
 * Get the mnemonic phrase from a mnemonic phrase or a `Uint8Array` of indices.
 * If the mnemonic is a `Uint8Array`, it is assumed to contain the indices of
 * the words in the wordlist.
 *
 * @param mnemonic - The mnemonic phrase or indices.
 * @param wordlist - The wordlist to use.
 * @returns The mnemonic phrase.
 */
function getMnemonicPhrase(
  mnemonic: string | Uint8Array,
  wordlist: string[],
): string {
  if (typeof mnemonic === 'string') {
    validateMnemonicPhrase(mnemonic);
    return mnemonic;
  }

  const mnemonicString = Array.from(new Uint16Array(mnemonic.buffer))
    .map((i) => wordlist[i])
    .join(' ');

  validateMnemonicPhrase(mnemonicString);

  return mnemonicString;
}

/**
 * Convert a BIP-39 mnemonic phrase to a seed.
 *
 * @param mnemonic - The BIP-39 mnemonic phrase to convert. If the mnemonic is a
 * `Uint8Array`, it is assumed to contain the indices of the words in the
 * English wordlist.
 * @param passphrase - The passphrase to use.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 */
export async function mnemonicToSeed(
  mnemonic: string | Uint8Array,
  passphrase = '',
  cryptographicFunctions?: CryptographicFunctions,
) {
  const salt = `mnemonic${passphrase}`.normalize('NFKD');
  const mnemonicString = getMnemonicPhrase(mnemonic, englishWordlist);

  return await pbkdf2Sha512(
    stringToBytes(mnemonicString),
    stringToBytes(salt),
    2048,
    64,
    cryptographicFunctions,
  );
}

/**
 * Convert a `Uint8Array` of bytes to an array of bits.
 *
 * @param bytes - The `Uint8Array` to convert.
 * @returns The array of bits.
 */
function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      // eslint-disable-next-line no-bitwise
      bits.push((byte >> i) & 1);
    }
  }

  return bits;
}

/**
 * Convert an array of bits to a `Uint8Array`.
 *
 * @param bits - The array of bits.
 * @returns The `Uint8Array`.
 */
export function bitsToBytes(bits: number[]): Uint8Array {
  if (bits.length % 8 !== 0) {
    throw new Error('The number of bits must be a multiple of 8.');
  }

  const bytes = new Uint8Array(bits.length / 8);

  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      const value = bits[i + j];
      assert(value === 0 || value === 1, 'Invalid bit value.');

      // eslint-disable-next-line no-bitwise
      byte |= value << (7 - j);
    }
    bytes[i / 8] = byte;
  }

  return bytes;
}

/**
 * Get the checksum for the entropy.
 *
 * @param entropy - The entropy.
 * @returns The checksum as an array of bits.
 */
function getChecksum(entropy: Uint8Array): number[] {
  const hash = sha256(entropy);
  return bytesToBits(hash).slice(0, entropy.length / 4);
}

/**
 * Convert a BIP-39 mnemonic phrase to entropy.
 *
 * @param mnemonic - The BIP-39 mnemonic phrase to convert.
 * @returns The entropy.
 */
export async function mnemonicToEntropy(
  mnemonic: string | Uint8Array,
): Promise<Uint8Array> {
  const words = getMnemonicPhrase(mnemonic, englishWordlist).split(' ');
  const bits = words.flatMap((word) => {
    const index = englishWordlist.indexOf(word);
    const binaryBits = [];

    for (let i = 10; i >= 0; i--) {
      // eslint-disable-next-line no-bitwise
      binaryBits.push((index >> i) & 1);
    }

    return binaryBits;
  });

  const checksumLength = bits.length % 32;
  const entropy = bits.slice(0, -checksumLength);
  const checksum = bits.slice(-checksumLength);

  const newChecksum = getChecksum(bitsToBytes(entropy));

  assert(
    checksum.length === newChecksum.length &&
      checksum.every((bit, index) => bit === newChecksum[index]),
    'Invalid checksum: The checksum does not match the entropy.',
  );

  return bitsToBytes(entropy);
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
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The node.
 */
export async function deriveChildKey(
  { path, curve }: DeriveChildKeyArgs,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<SLIP10Node> {
  switch (curve.masterNodeGenerationSpec) {
    case 'slip10':
      return createBip39KeyFromSeed(
        await mnemonicToSeed(path, '', cryptographicFunctions),
        curve,
        cryptographicFunctions,
      );
    case 'cip3':
      return entropyToCip3MasterNode(
        await mnemonicToEntropy(path),
        curve,
        cryptographicFunctions,
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
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns An object containing the corresponding BIP-39 master key and chain
 * code.
 */
export async function createBip39KeyFromSeed(
  seed: Uint8Array,
  curve: Extract<Curve, { masterNodeGenerationSpec: 'slip10' }>,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<SLIP10Node> {
  assert(
    seed.length >= 16 && seed.length <= 64,
    'Invalid seed: The seed must be between 16 and 64 bytes long.',
  );

  const key = await hmacSha512(curve.secret, seed, cryptographicFunctions);
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

  return SLIP10Node.fromExtendedKey(
    {
      privateKey,
      chainCode,
      masterFingerprint,
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      curve: curve.name,
    },
    cryptographicFunctions,
  );
}

/**
 * Create a {@link SLIP10Node} from BIP-39 entropy.
 * This function is consistent with the Icarus derivation scheme.
 * Icarus root key derivation scheme: https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/Icarus.md.
 * CIP3: https://github.com/cardano-foundation/CIPs/blob/09d7d8ee1bd64f7e6b20b5a6cae088039dce00cb/CIP-0003/CIP-0003.md#master-key-generation.
 *
 * @param entropy - The entropy value.
 * @param curve - The curve to use.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The root key pair consisting of 64-byte private key and 32-byte chain code.
 */
export async function entropyToCip3MasterNode(
  entropy: Uint8Array,
  curve: Extract<Curve, { masterNodeGenerationSpec: 'cip3' }>,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<SLIP10Node> {
  assert(
    entropy.length >= 16 && entropy.length <= 64,
    'Invalid entropy: The entropy must be between 16 and 64 bytes long.',
  );

  const rootNode = await pbkdf2Sha512(
    curve.secret,
    entropy,
    4096,
    96,
    cryptographicFunctions,
  );

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

  return SLIP10Node.fromExtendedKey(
    {
      privateKey,
      chainCode,
      masterFingerprint,
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      curve: curve.name,
    },
    cryptographicFunctions,
  );
}
