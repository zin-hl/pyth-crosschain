import { Account } from "viem";
import { mnemonicToAccount } from "viem/accounts";
import { KMSSigner } from "./kms-signer";

export interface SignerConfig {
  kmsKeyId?: string;
  kmsRegion?: string;
  mnemonic?: string;
}

export async function createSigner(config: SignerConfig): Promise<Account> {
  // Validate that either KMS or mnemonic is provided
  const hasKms = config.kmsKeyId && config.kmsRegion;
  const hasMnemonic = config.mnemonic;

  if (hasKms && hasMnemonic) {
    throw new Error(
      "Cannot provide both KMS credentials and mnemonic. Please choose one authentication method.",
    );
  }

  if (!hasKms && !hasMnemonic) {
    throw new Error(
      "Must provide either KMS credentials (kms-key-id and kms-region) or mnemonic.",
    );
  }

  // Create KMS signer if KMS credentials are provided
  if (hasKms) {
    if (!config.kmsRegion) {
      throw new Error("kms-region is required when using kms-key-id");
    }

    const kmsSigner = new KMSSigner(config.kmsKeyId!, config.kmsRegion);
    await kmsSigner.initialize();
    return kmsSigner.toAccount();
  }

  // Otherwise, use mnemonic
  return mnemonicToAccount(config.mnemonic!);
}
