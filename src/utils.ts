import {
  BASE_64_KEY_LENGTH,
  BASE_64_REGEX,
  BASE_64_ZERO,
  BUFFER_KEY_LENGTH,
  BIP44PurposeNode,
  UnhardenedBIP32Node,
  CoinTypeHDPathString,
  CoinTypeToAddressTuple,
  HardenedBIP32Node,
  ChangeHDPathString,
  HEXADECIMAL_KEY_LENGTH,
} from './constants';

export function getBIP44CoinTypePathString(
  coin_type: number,
): CoinTypeHDPathString {
  return `m / ${BIP44PurposeNode} / ${getUnhardenedBIP32Node(coin_type)}'`;
}

interface BIP44PathIndices {
  coin_type: number;
  account?: number;
  change?: number;
  address_index: number;
}

export type CoinTypeToAddressIndices = Pick<
  BIP44PathIndices,
  'account' | 'change' | 'address_index'
>;

export function getBIP44ChangePathString(
  coinTypePath: CoinTypeHDPathString,
  indices: Omit<CoinTypeToAddressIndices, 'address_index'>,
): ChangeHDPathString {
  return `${coinTypePath} / ${getHardenedBIP32Node(
    indices.account || 0,
  )} / ${getUnhardenedBIP32Node(indices.change || 0)}`;
}

export function getBIP44AddressPathTuple({
  account = 0,
  change = 0,
  address_index,
}: CoinTypeToAddressIndices): CoinTypeToAddressTuple {
  return [
    getHardenedBIP32Node(account),
    getUnhardenedBIP32Node(change),
    getUnhardenedBIP32Node(address_index),
  ] as const;
}

export function getHardenedBIP32Node(index: number): HardenedBIP32Node {
  return `${getUnhardenedBIP32Node(index)}'`;
}

export function getUnhardenedBIP32Node(index: number): UnhardenedBIP32Node {
  validateBIP32Index(index);
  return `bip32:${index}`;
}

export function validateBIP32Index(addressIndex: number) {
  if (!isValidBIP32Index(addressIndex)) {
    throw new Error(`Invalid BIP-32 index: Must be a non-negative integer.`);
  }
}

export function isValidBIP32Index(index: number): boolean {
  return Number.isInteger(index) && index >= 0;
}

export function isHardened(bip32Token: string): boolean {
  return bip32Token.endsWith(`'`);
}

export function stripHexPrefix(hexString: string): string {
  return hexString.replace(/^0x/iu, '');
}

export function isValidHexString(hexString: string): boolean {
  return /^(?:0x)?[a-f0-9]+$/iu.test(hexString);
}

export function base64StringToBuffer(base64String: string) {
  return Buffer.from(base64String, 'base64');
}

export function hexStringToBuffer(hexString: string) {
  return Buffer.from(stripHexPrefix(hexString), 'hex');
}

export function bufferToBase64String(input: Buffer) {
  return input.toString('base64');
}

export function isValidBufferKey(buffer: Buffer): boolean {
  if (buffer.length !== BUFFER_KEY_LENGTH) {
    return false;
  }

  for (const byte of buffer) {
    if (byte !== 0) {
      return true;
    }
  }
  return false;
}

function isValidBase64String(input: string) {
  return BASE_64_REGEX.test(input);
}

export function isValidHexStringKey(stringKey: string): boolean {
  if (!isValidHexString(stringKey)) {
    return false;
  }

  const stripped = stripHexPrefix(stringKey);
  if (stripped.length !== HEXADECIMAL_KEY_LENGTH) {
    return false;
  }

  if (/^0+$/iu.test(stripped)) {
    return false;
  }
  return true;
}

export function isValidBase64StringKey(stringKey: string): boolean {
  if (!isValidBase64String(stringKey)) {
    return false;
  }

  if (stringKey.length !== BASE_64_KEY_LENGTH) {
    return false;
  }

  if (stringKey === BASE_64_ZERO) {
    return false;
  }
  return true;
}
