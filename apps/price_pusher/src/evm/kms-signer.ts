import { KMSClient, GetPublicKeyCommand, SignCommand } from "@aws-sdk/client-kms";
import {
  Hex,
  toHex,
  keccak256,
  LocalAccount,
  hashMessage,
  Address,
  serializeTransaction,
  TransactionSerializable,
} from "viem";
import { toAccount } from "viem/accounts";
import BN from "bn.js";
import asn1 from "asn1.js";

// ASN.1 DER sequence parser for ECDSA signature
const ECDSASignature = asn1.define("ECDSASignature", function (this: any) {
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

// secp256k1 curve order for signature normalization
const SECP256K1_N = new BN(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  16,
);

export class KMSSigner {
  private kmsClient: KMSClient;
  private keyId: string;
  private publicKey: Buffer | undefined;
  private address: Address | undefined;

  constructor(keyId: string, region: string) {
    this.keyId = keyId;
    this.kmsClient = new KMSClient({ region });
  }

  async initialize(): Promise<void> {
    await this.loadPublicKey();
  }

  private async loadPublicKey(): Promise<void> {
    const command = new GetPublicKeyCommand({
      KeyId: this.keyId,
    });

    const response = await this.kmsClient.send(command);

    if (!response.PublicKey) {
      throw new Error("Failed to retrieve public key from KMS");
    }

    this.publicKey = Buffer.from(response.PublicKey);
    this.address = this.deriveAddress(this.publicKey);
  }

  private deriveAddress(publicKey: Buffer): Address {
    // The public key from KMS is in DER format for secp256k1
    // We need to extract the uncompressed public key (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
    // The DER format has a header, we skip it and take the last 65 bytes
    const uncompressedKey = publicKey.slice(-65);

    if (uncompressedKey[0] !== 0x04 || uncompressedKey.length !== 65) {
      throw new Error("Invalid public key format");
    }

    // Ethereum address is the last 20 bytes of the keccak256 hash of the public key (without the 0x04 prefix)
    const publicKeyWithoutPrefix = uncompressedKey.slice(1);
    const hash = keccak256(publicKeyWithoutPrefix);
    const address = `0x${hash.slice(-40)}` as Address;

    return address;
  }

  async signMessage(message: Hex): Promise<Hex> {
    const messageHash = hashMessage({ raw: message });
    return this.signHash(messageHash);
  }

  async signHash(hash: Hex): Promise<Hex> {
    const hashBuffer = Buffer.from(hash.slice(2), "hex");

    const command = new SignCommand({
      KeyId: this.keyId,
      Message: hashBuffer,
      MessageType: "DIGEST",
      SigningAlgorithm: "ECDSA_SHA_256",
    });

    const response = await this.kmsClient.send(command);

    if (!response.Signature) {
      throw new Error("Failed to sign with KMS");
    }

    const signature = Buffer.from(response.Signature);

    // Parse DER-encoded signature
    const decoded = ECDSASignature.decode(signature, "der");
    let r = new BN(decoded.r);
    let s = new BN(decoded.s);

    // Normalize s to low form (required by Ethereum)
    const halfN = SECP256K1_N.shrn(1);
    if (s.gt(halfN)) {
      s = SECP256K1_N.sub(s);
    }

    // Calculate recovery ID (v)
    const v = await this.calculateRecoveryId(hash, r, s);

    // Construct signature in the format expected by viem
    const rHex = toHex(r.toArrayLike(Buffer, "be", 32));
    const sHex = toHex(s.toArrayLike(Buffer, "be", 32));
    const vHex = toHex(v);

    // Concatenate r, s, v
    return `${rHex}${sHex.slice(2)}${vHex.slice(2)}` as Hex;
  }

  private async calculateRecoveryId(
    hash: Hex,
    r: BN,
    s: BN,
  ): Promise<number> {
    // Try both recovery IDs (0 and 1, which map to v=27 and v=28 in Ethereum)
    for (let recoveryId = 0; recoveryId <= 1; recoveryId++) {
      try {
        const recoveredAddress = await this.recoverAddress(
          hash,
          r,
          s,
          recoveryId,
        );
        if (
          recoveredAddress.toLowerCase() === this.address?.toLowerCase()
        ) {
          return recoveryId + 27; // Ethereum uses 27/28
        }
      } catch {
        // Try next recovery ID
        continue;
      }
    }

    throw new Error("Failed to calculate recovery ID");
  }

  private async recoverAddress(
    hash: Hex,
    r: BN,
    s: BN,
    recoveryId: number,
  ): Promise<Address> {
    const rHex = toHex(r.toArrayLike(Buffer, "be", 32));
    const sHex = toHex(s.toArrayLike(Buffer, "be", 32));
    const vHex = toHex(recoveryId + 27);

    const signature = `${rHex}${sHex.slice(2)}${vHex.slice(2)}` as Hex;

    // Use viem's built-in recovery
    const { recoverAddress } = await import("viem");
    return recoverAddress({ hash, signature });
  }

  getAddress(): Address {
    if (!this.address) {
      throw new Error("KMSSigner not initialized. Call initialize() first.");
    }
    return this.address;
  }

  async signTransaction(
    transaction: TransactionSerializable,
  ): Promise<Hex> {
    // Serialize the transaction to get the hash
    const serializedTx = serializeTransaction(transaction);
    const txHash = keccak256(serializedTx);

    // Sign the transaction hash
    const signature = await this.signHash(txHash);

    // Parse the signature to get r, s, v
    const r = `0x${signature.slice(2, 66)}` as Hex;
    const s = `0x${signature.slice(66, 130)}` as Hex;
    const v = parseInt(signature.slice(130), 16);

    // Serialize the transaction with the signature
    return serializeTransaction(transaction, { r, s, v: BigInt(v) });
  }

  toAccount(): LocalAccount {
    if (!this.address) {
      throw new Error("KMSSigner not initialized. Call initialize() first.");
    }

    return toAccount({
      address: this.address,
      signMessage: async ({ message }) => {
        if (typeof message === "string") {
          return this.signMessage(toHex(message));
        }
        // message.raw is Hex type, which is already `0x${string}`
        return this.signMessage(message.raw as Hex);
      },
      signTransaction: async (transaction) => {
        return this.signTransaction(transaction);
      },
      signTypedData: async (typedData) => {
        throw new Error("signTypedData not implemented for KMSSigner");
      },
    });
  }
}
