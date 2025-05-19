import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import { HDKey } from '@scure/bip32';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';

// Configure BIP32 with noble secp256k1 implementation
// @ts-expect-error Type definitions mismatch
const hdKeyFactory = HDKey.deriveHDKeyFactory(secp.secp256k1);

export interface HDWallet {
  readonly mnemonic: string;
  readonly publicKey: string;
  derivePath(path: string): HDWallet;
  signMessage(message: string): Uint8Array;
}

export function generateWalletMnemonic(): string {
  return generateMnemonic(256 as unknown as Parameters<typeof generateMnemonic>[0]); // Correct strength type with safer assertion
}

export function createWalletFromMnemonic(mnemonic: string): HDWallet {
  const seed = mnemonicToSeedSync(mnemonic);
  const root = hdKeyFactory.fromSeed(seed);

  return {
    mnemonic,
    publicKey: bytesToHex(root.publicKey),
    derivePath(path: string) {
      const childNode = root.derive(path);
      return createWalletFromNode(childNode, mnemonic);
    },
    signMessage(message: string): Uint8Array {
      return secp.sign(nobleSha256(message), root.privateKey!).toCompactRawBytes();
    }
  };
}

function createWalletFromNode(node: HDKey, mnemonic: string): HDWallet {
  return {
    mnemonic,
    publicKey: bytesToHex(node.publicKey!),
    derivePath(path: string) {
      return createWalletFromNode(node.derive(path), mnemonic);
    },
    signMessage(message: string): Uint8Array {
      return secp.sign(sha256(message), node.privateKey!).toCompactRawBytes();
    }
  };
}

export function getPublicKeyFromMnemonic(mnemonic: string): string {
  const wallet = createWalletFromMnemonic(mnemonic);
  return wallet.derivePath("m/44'/0'/0'/0/0").publicKey;
}

// React Native compatible utilities
function sha256(message: string): Uint8Array {
  return nobleSha256(new TextEncoder().encode(message));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
