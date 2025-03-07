import { mnemonicToEntropy } from '@metamask/scure-bip39';
import { wordlist as englishWordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import { assert, assertExhaustive, stringToBytes } from '@metamask/utils';

import type { DeriveChildKeyArgs } from '.';
import type {
  BIP39Node,
  BIP39StringNode,
  Network,
  RootedSLIP10PathTuple,
  RootedSLIP10SeedPathTuple,
} from '../constants';
import { BYTES_KEY_LENGTH } from '../constants';
import type { CryptographicFunctions } from '../cryptography';
import { hmacSha512, pbkdf2Sha512 } from '../cryptography';
import type { Curve, SupportedCurve } from '../curves';
import { getCurveByName } from '../curves';
import { PUBLIC_KEY_GUARD } from '../guard';
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
function validateMnemonicPhrase(mnemonicPhrase: string): void {
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
): Uint8Array {
  if (typeof mnemonic === 'string') {
    validateMnemonicPhrase(mnemonic);
    return stringToBytes(mnemonic.normalize('NFKD'));
  }

  const mnemonicString = Array.from(new Uint16Array(mnemonic.buffer))
    .map((i) => wordlist[i])
    .join(' ');

  validateMnemonicPhrase(mnemonicString);
  return stringToBytes(mnemonicString);
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
 * @returns The seed.
 */
export async function mnemonicToSeed(
  mnemonic: string | Uint8Array,
  passphrase = '',
  cryptographicFunctions?: CryptographicFunctions,
): Promise<Uint8Array> {
  const salt = `mnemonic${passphrase}`.normalize('NFKD');
  return await pbkdf2Sha512(
    encodeMnemonicPhrase(mnemonic, englishWordlist),
    stringToBytes(salt),
    2048,
    64,
    cryptographicFunctions,
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
 * Convert a multi path to a BIP-39 mnemonic phrase.
 *
 * @param value - The multi path to convert.
 * @returns The BIP-39 mnemonic phrase.
 */
export function multipathToBip39Mnemonic(
  value: BIP39Node,
): string | Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }

  assert(
    value.startsWith('bip39:'),
    'Invalid HD path segment: The BIP-39 path must start with "bip39:".',
  );

  return value.slice(6);
}

export type GetDerivationPathWithSeedOptions = {
  path: RootedSLIP10PathTuple;
  curve: SupportedCurve;
};

/**
 * Get a {@link RootedSLIP10SeedPathTuple} from a {@link RootedSLIP10PathTuple}.
 *
 * @param options - The options for getting the derivation path.
 * @param options.path - The derivation path to convert.
 * @param options.curve - The curve to use for derivation.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The derivation path with the seed, or entropy in the case of CIP-3.
 */
export async function getDerivationPathWithSeed(
  { path, curve: curveName }: GetDerivationPathWithSeedOptions,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<RootedSLIP10SeedPathTuple> {
  const [mnemonicPhrase, ...rest] = path;
  const plainMnemonicPhrase = multipathToBip39Mnemonic(mnemonicPhrase);

  const curve = getCurveByName(curveName);
  switch (curve.masterNodeGenerationSpec) {
    case 'slip10': {
      const seed = await mnemonicToSeed(
        plainMnemonicPhrase,
        '',
        cryptographicFunctions,
      );
      return [seed, ...rest];
    }

    case 'cip3': {
      const seed = mnemonicToEntropy(plainMnemonicPhrase, englishWordlist);
      return [seed, ...rest];
    }

    /* istanbul ignore next */
    default:
      return assertExhaustive(curve);
  }
}

/**
 * Create a {@link SLIP10Node} from a BIP-39 seed.
 *
 * @param options - The options for creating the node.
 * @param options.path - The multi path. This is expected to be the BIP-39 seed,
 * or the entropy in the case of CIP-3, not the mnemonic phrase itself.
 * @param options.curve - The curve to use for derivation.
 * @param options.network - The network for the node. This is only used for
 * extended keys, and defaults to `mainnet`.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The node.
 */
export async function deriveChildKey(
  { path, curve, network }: DeriveChildKeyArgs,
  cryptographicFunctions?: CryptographicFunctions,
): Promise<SLIP10Node> {
  assert(
    path instanceof Uint8Array,
    'Invalid path: The path must be a Uint8Array.',
  );

  switch (curve.masterNodeGenerationSpec) {
    case 'slip10':
      return createBip39KeyFromSeed(
        path,
        curve,
        network,
        cryptographicFunctions,
      );
    case 'cip3':
      return entropyToCip3MasterNode(
        path,
        curve,
        network,
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
 * @param network - The network for the node. This is only used for extended
 * keys, and defaults to `mainnet`.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns An object containing the corresponding BIP-39 master key and chain
 * code.
 */
export async function createBip39KeyFromSeed(
  seed: Uint8Array,
  curve: Extract<Curve, { masterNodeGenerationSpec: 'slip10' }>,
  network?: Network | undefined,
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

  const publicKey = curve.getPublicKey(privateKey, false);
  const masterFingerprint = getFingerprint(
    curve.compressPublicKey(publicKey),
    curve.compressedPublicKeyLength,
  );

  return SLIP10Node.fromExtendedKey(
    {
      privateKey,
      publicKey,
      chainCode,
      masterFingerprint,
      network,
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      curve: curve.name,
      guard: PUBLIC_KEY_GUARD,
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
 * @param network - The network for the node. This is only used for extended
 * keys, and defaults to `mainnet`.
 * @param cryptographicFunctions - The cryptographic functions to use. If
 * provided, these will be used instead of the built-in implementations.
 * @returns The root key pair consisting of 64-byte private key and 32-byte chain code.
 */
export async function entropyToCip3MasterNode(
  entropy: Uint8Array,
  curve: Extract<Curve, { masterNodeGenerationSpec: 'cip3' }>,
  network?: Network | undefined,
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
    curve.getPublicKey(privateKey),
    curve.compressedPublicKeyLength,
  );

  return SLIP10Node.fromExtendedKey(
    {
      privateKey,
      chainCode,
      masterFingerprint,
      network,
      depth: 0,
      parentFingerprint: 0,
      index: 0,
      curve: curve.name,
    },
    cryptographicFunctions,
  );
}
