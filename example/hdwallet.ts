import {BIP32Factory, type BIP32Interface} from 'bip32'
import * as bip39 from 'bip39'
import * as bitcoin from 'bitcoinjs-lib'
import * as crypto from 'crypto'
import * as fs from 'fs'
import * as ecc from 'tiny-secp256k1'

const bip32 = BIP32Factory(ecc)

// Generate a new HD wallet
async function createHDWallet(): Promise<{
  mnemonic: string
  seed: Buffer
  root: BIP32Interface
}> {
  const mnemonic = bip39.generateMnemonic(256)
  const seed = await bip39.mnemonicToSeed(mnemonic)
  const root = bip32.fromSeed(seed)

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
  const key = crypto.scryptSync(password, 'salt', 32)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

  let encrypted = cipher.update(walletJson, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  const authTag = cipher.getAuthTag().toString('hex')

  // Save encrypted data
  fs.writeFileSync(
    filePath,
    JSON.stringify({
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
  const key = crypto.scryptSync(password, 'salt', 32)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(Buffer.from(fileData.authTag, 'hex'))

  // Decrypt
  let decrypted = decipher.update(fileData.encryptedData, 'hex', 'utf8')
  decrypted += decipher.final('utf8')

  const walletData = JSON.parse(decrypted)

  // Reconstruct HD wallet
  const root = bip32.fromBase58(
    walletData.xpriv,
    bitcoin.networks.bitcoin as any,
  )

  return {
    mnemonic: walletData.mnemonic,
    root,
  }
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
      pubkey: Buffer.from(derivedKey.publicKey) as Buffer,
      network: bitcoin.networks.bitcoin,
    }).address

    console.log('\n=== Wallet Demo Results ===')
    console.log('Generated mnemonic:', wallet.mnemonic)
    console.log('Recovered mnemonic:', loadedWallet.mnemonic)
    console.log('Derived Bitcoin address:', address)
    console.log('===========================')
  } catch (err) {
    console.error('Error:', err)
    process.exit(1)
  }
}

main().catch(console.error)
