package com.example.gateway.service;



import com.example.gateway.adapter.keyvault.client.AzureKeyVaultClient;
import com.example.gateway.exception.EncryptionException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Centralized Encryption Service
 *
 * AES-256-GCM encryption with Key Vault integration
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EncryptionService {

  private final AzureKeyVaultClient keyVaultClient;

  private static final int GCM_TAG_LENGTH = 128;
  private static final int GCM_IV_LENGTH = 12;
  private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
  private static final SecureRandom secureRandom = new SecureRandom();

  private volatile SecretKey currentKey;
  private volatile String currentKeyVersion;

  @PostConstruct
  public void initialize() {
    loadEncryptionKey();
  }

  /**
   * Encrypt data using AES-256-GCM
   */
  public String encrypt(String plaintext) {
    try {
      byte[] iv = new byte[GCM_IV_LENGTH];
      secureRandom.nextBytes(iv);

      Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
      cipher.init(Cipher.ENCRYPT_MODE, getEncryptionKey(), spec);

      byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

      byte[] combined = new byte[iv.length + encrypted.length];
      System.arraycopy(iv, 0, combined, 0, iv.length);
      System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

      return Base64.getEncoder().encodeToString(combined);

    } catch (Exception e) {
      log.error("Encryption failed", e);
      throw new EncryptionException("Failed to encrypt data", e);
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   */
  public String decrypt(String encryptedData) {
    try {
      byte[] combined = Base64.getDecoder().decode(encryptedData);

      byte[] iv = new byte[GCM_IV_LENGTH];
      byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
      System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
      System.arraycopy(combined, GCM_IV_LENGTH, encrypted, 0, encrypted.length);

      Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
      cipher.init(Cipher.DECRYPT_MODE, getEncryptionKey(), spec);

      byte[] decrypted = cipher.doFinal(encrypted);
      return new String(decrypted, StandardCharsets.UTF_8);

    } catch (Exception e) {
      log.error("Decryption failed", e);
      throw new EncryptionException("Failed to decrypt data", e);
    }
  }

  /**
   * Refresh encryption key
   */
  public void refreshKey() {
    loadEncryptionKey();
  }

  private SecretKey getEncryptionKey() {
    if (currentKey == null) {
      synchronized (this) {
        if (currentKey == null) {
          loadEncryptionKey();
        }
      }
    }
    return currentKey;
  }

  private void loadEncryptionKey() {
    try {
      String keyBase64 = keyVaultClient.getSecret("session-encryption-key");
      byte[] keyBytes = Base64.getDecoder().decode(keyBase64);

      if (keyBytes.length != 32) {
        throw new EncryptionException("Invalid key length: expected 256 bits");
      }

      currentKey = new SecretKeySpec(keyBytes, "AES");
      currentKeyVersion = String.valueOf(System.currentTimeMillis());

      log.info("Encryption key loaded successfully, version: {}", currentKeyVersion);

    } catch (Exception e) {
      log.error("Failed to load encryption key", e);
      throw new EncryptionException("Failed to initialize encryption key", e);
    }
  }
}
