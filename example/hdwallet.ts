import {BIP32Factory} from 'bip32'
import * as ecc from 'tiny-secp256k1'
const bip32 = BIP32Factory(ecc)
import  {type BIP32Interface} from 'bip32'
import * as bip39 from 'bip39'
import * as bitcoin from 'bitcoinjs-lib'
import {networks} from 'bitcoinjs-lib'
import * as crypto from 'crypto'
import * as fs from 'fs'

// Generate a new HD wallet
async function createHDWallet(): Promise<{
  mnemonic: string
  seed: Buffer
  root: BIP32Interface
}> {
  const mnemonic = bip39.generateMnemonic(256)
  const seed = await bip39.mnemonicToSeed(mnemonic)
  const root = bip32.fromSeed(Buffer.from(seed), networks.bitcoin)

  return {mnemonic, seed, root}
}

// Encrypt and save to file
function saveWalletToFile(
  walletData: {mnemonic: string; root: BIP32Interface},
  filePath: string,
  password: string,
): void {
  // Convert wallet data to JSON
  const walletJson = JSON.stringify({
    mnemonic: walletData.mnemonic,
    xpriv: walletData.root.toBase58(), // Serialized extended private key
  })

  // Encryption
  const iv = crypto.randomBytes(16)
  const salt = crypto.randomBytes(16)
  const key = crypto.scryptSync(password, salt, 32) as Buffer
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

  let encrypted = cipher.update(walletJson, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  const authTag = cipher.getAuthTag().toString('hex')

  // Save encrypted data
  fs.writeFileSync(
    filePath,
    JSON.stringify({
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      encryptedData: encrypted,
      authTag,
    }),
  )

  console.log(`Wallet saved securely to ${filePath}`)
}

function loadWalletFromFile(
  filePath: string,
  password: string,
): {mnemonic: string; root: BIP32Interface} {
  // Read encrypted file
  const fileData = JSON.parse(fs.readFileSync(filePath, 'utf8'))

  // Prepare decryption
  const iv = Buffer.from(fileData.iv, 'hex')
  const salt = Buffer.from(fileData.salt, 'hex')
  const key = crypto.scryptSync(password, salt, 32)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(Buffer.from(fileData.authTag, 'hex'))

  // Decrypt
  let decrypted = decipher.update(fileData.encryptedData, 'hex', 'utf8')
  decrypted += decipher.final('utf8')

  const walletData = JSON.parse(decrypted)

  // Reconstruct HD wallet
  const root = bip32.fromBase58(walletData.xpriv, networks.bitcoin)

  return {
    mnemonic: walletData.mnemonic,
    root,
  }
}

function encryptWithPublicKey(text: string, publicKey: Buffer): string {
  const eph = crypto.createECDH('secp256k1')
  eph.generateKeys()
  const sharedSecret = eph.computeSecret(publicKey)
  const derivedKey = crypto.hkdfSync('sha256', sharedSecret, '', '', 32)
  const iv = crypto.randomBytes(16)

  const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv)
  let encrypted = cipher.update(text, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  const authTag = cipher.getAuthTag().toString('hex')

  return JSON.stringify({
    ephemeralPublicKey: eph.getPublicKey().toString('hex'),
    iv: iv.toString('hex'),
    encryptedData: encrypted,
    authTag, // 🧩 this was missing
  })
}
function decryptWithPrivateKey(
  encryptedData: string,
  privateKey: Buffer,
): string {
  const data = JSON.parse(encryptedData)

  const ecdh = crypto.createECDH('secp256k1')
  ecdh.setPrivateKey(privateKey)
  const sharedSecret = ecdh.computeSecret(
    Buffer.from(data.ephemeralPublicKey, 'hex'),
  )
  const derivedKey = crypto.hkdfSync('sha256', sharedSecret, '', '', 32)

  const iv = Buffer.from(data.iv, 'hex')
  const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv)
  decipher.setAuthTag(Buffer.from(data.authTag, 'hex')) // ✅ this was commented out

  let decrypted = decipher.update(data.encryptedData, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}

async function main() {
  try {
    // Create new wallet
    const wallet = await createHDWallet()
    console.log('New wallet mnemonic:', wallet.mnemonic)

    // Save to file (with password)
    const password = 'strong-password-123'
    saveWalletToFile(
      {mnemonic: wallet.mnemonic, root: wallet.root},
      './wallet.enc',
      password,
    )

    // Load from file
    const loadedWallet = loadWalletFromFile('./wallet.enc', password)
    console.log('Recovered mnemonic:', loadedWallet.mnemonic)

    // Verify derivation works
    const path = "m/84'/0'/0'/0/0"
    const derivedKey = loadedWallet.root.derivePath(path)
    const address = bitcoin.payments.p2wpkh({
      pubkey: Buffer.from(derivedKey.publicKey),
      network: bitcoin.networks.bitcoin,
    }).address

    // Test encryption/decryption
    const testMessage = 'This is a secret message!'
    console.log('\nOriginal message:', testMessage)

    // Encrypt with public key
    const encrypted = encryptWithPublicKey(
      testMessage,
      Buffer.from(derivedKey.publicKey),
    )
    console.log('Encrypted message:', encrypted)

    // Decrypt with private key
    if (!derivedKey.privateKey) {
      throw new Error('Cannot decrypt - no private key available')
    }
    const decrypted = decryptWithPrivateKey(
      encrypted,
      Buffer.from(derivedKey.privateKey),
    )
    console.log('Decrypted message:', decrypted)

    console.log('\n=== Wallet Demo Results ===')
    console.log('Generated mnemonic:', wallet.mnemonic)
    console.log('Recovered mnemonic:', loadedWallet.mnemonic)
    console.log('Derived Bitcoin address:', address)
    console.log(
      'Encryption/Decryption test:',
      testMessage === decrypted ? 'SUCCESS' : 'FAILED',
    )
    console.log('===========================')
  } catch (err) {
    console.error('Error:', err)
    process.exit(1)
  }
}

main().catch(console.error)
