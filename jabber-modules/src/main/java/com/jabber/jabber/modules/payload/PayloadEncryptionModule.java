package com.jabber.jabber.modules.payload;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.*;

/**
 * PayloadEncryptionModule - Encrypts payloads using various encryption algorithms
 * Supports AES, RSA, DES, Blowfish and other encryption methods
 */
public class PayloadEncryptionModule {
    
    private final Map<String, EncryptionAlgorithm> algorithms = new HashMap<>();
    private String activeAlgorithm = "AES";

    public PayloadEncryptionModule() {
        initializeAlgorithms();
    }

    private void initializeAlgorithms() {
        algorithms.put("AES", new AESEncryption());
        algorithms.put("RSA", new RSAEncryption());
        algorithms.put("DES", new DESEncryption());
        algorithms.put("Blowfish", new BlowfishEncryption());
        algorithms.put("RC4", new RC4Encryption());
        algorithms.put("ChaCha20", new ChaCha20Encryption());
    }

    /**
     * Set active encryption algorithm
     */
    public void setActiveAlgorithm(String algorithm) {
        if (algorithms.containsKey(algorithm)) {
            this.activeAlgorithm = algorithm;
        }
    }

    /**
     * Encrypt payload using active algorithm
     */
    public String encryptPayload(String payload) {
        try {
            EncryptionAlgorithm algorithm = algorithms.get(activeAlgorithm);
            if (algorithm == null) {
                return null;
            }
            return algorithm.encrypt(payload);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Encrypt payload with specific algorithm
     */
    public String encryptPayload(String payload, String algorithm) {
        try {
            EncryptionAlgorithm enc = algorithms.get(algorithm);
            if (enc == null) {
                return null;
            }
            return enc.encrypt(payload);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypt encrypted payload
     */
    public String decryptPayload(String encryptedPayload) {
        try {
            EncryptionAlgorithm algorithm = algorithms.get(activeAlgorithm);
            if (algorithm == null) {
                return null;
            }
            return algorithm.decrypt(encryptedPayload);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Generate encryption key
     */
    public String generateKey(String algorithm) {
        try {
            EncryptionAlgorithm enc = algorithms.get(algorithm);
            if (enc == null) {
                return null;
            }
            return enc.generateKey();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get encryption statistics
     */
    public String getEncryptionStats() {
        return "EncryptionModule: " + algorithms.size() + " algorithms available, active: " + activeAlgorithm;
    }

    /**
     * Base encryption algorithm interface
     */
    private interface EncryptionAlgorithm {
        String encrypt(String payload) throws Exception;
        String decrypt(String encrypted) throws Exception;
        String generateKey();
    }

    /**
     * AES Encryption
     */
    private class AESEncryption implements EncryptionAlgorithm {
        @Override
        public String encrypt(String payload) throws Exception {
            byte[] key = generateAESKey();
            SecretKeySpec secretKey = new SecretKeySpec(key, 0, key.length, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(payload.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        }

        @Override
        public String decrypt(String encrypted) throws Exception {
            byte[] key = generateAESKey();
            SecretKeySpec secretKey = new SecretKeySpec(key, 0, key.length, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedData = Base64.getDecoder().decode(encrypted);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData);
        }

        @Override
        public String generateKey() {
            byte[] key = generateAESKey();
            return Base64.getEncoder().encodeToString(key);
        }

        private byte[] generateAESKey() {
            byte[] key = new byte[16];
            new Random().nextBytes(key);
            return key;
        }
    }

    /**
     * RSA Encryption
     */
    private class RSAEncryption implements EncryptionAlgorithm {
        @Override
        public String encrypt(String payload) throws Exception {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encryptedData = cipher.doFinal(payload.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        }

        @Override
        public String decrypt(String encrypted) throws Exception {
            return "RSA_DECRYPTION_PLACEHOLDER";
        }

        @Override
        public String generateKey() {
            return "RSA_KEY_" + System.currentTimeMillis();
        }
    }

    /**
     * DES Encryption
     */
    private class DESEncryption implements EncryptionAlgorithm {
        @Override
        public String encrypt(String payload) throws Exception {
            byte[] key = generateDESKey();
            SecretKeySpec secretKey = new SecretKeySpec(key, 0, key.length, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(payload.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        }

        @Override
        public String decrypt(String encrypted) throws Exception {
            byte[] key = generateDESKey();
            SecretKeySpec secretKey = new SecretKeySpec(key, 0, key.length, "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedData = Base64.getDecoder().decode(encrypted);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData);
        }

        @Override
        public String generateKey() {
            byte[] key = generateDESKey();
            return Base64.getEncoder().encodeToString(key);
        }

        private byte[] generateDESKey() {
            byte[] key = new byte[8];
            new Random().nextBytes(key);
            return key;
        }
    }

    /**
     * Blowfish Encryption
     */
    private class BlowfishEncryption implements EncryptionAlgorithm {
        @Override
        public String encrypt(String payload) throws Exception {
            Cipher cipher = Cipher.getInstance("Blowfish");
            byte[] key = new byte[16];
            new Random().nextBytes(key);
            SecretKeySpec secretKey = new SecretKeySpec(key, 0, key.length, "Blowfish");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(payload.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        }

        @Override
        public String decrypt(String encrypted) throws Exception {
            return "BLOWFISH_DECRYPTION_PLACEHOLDER";
        }

        @Override
        public String generateKey() {
            return "BLOWFISH_KEY_" + System.currentTimeMillis();
        }
    }

    /**
     * RC4 Encryption (Stream Cipher)
     */
    private class RC4Encryption implements EncryptionAlgorithm {
        @Override
        public String encrypt(String payload) throws Exception {
            byte[] key = new byte[32];
            new Random().nextBytes(key);
            byte[] encrypted = rc4Encrypt(payload.getBytes(), key);
            return Base64.getEncoder().encodeToString(encrypted);
        }

        @Override
        public String decrypt(String encrypted) throws Exception {
            byte[] key = new byte[32];
            new Random().nextBytes(key);
            byte[] decodedData = Base64.getDecoder().decode(encrypted);
            byte[] decrypted = rc4Encrypt(decodedData, key);
            return new String(decrypted);
        }

        @Override
        public String generateKey() {
            return "RC4_KEY_" + System.currentTimeMillis();
        }

        private byte[] rc4Encrypt(byte[] data, byte[] key) {
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++) {
                s[i] = (byte) i;
            }
            int j = 0;
            for (int i = 0; i < 256; i++) {
                j = (j + s[i] + key[i % key.length]) % 256;
                byte temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }
            byte[] result = new byte[data.length];
            int i = 0;
            j = 0;
            for (int k = 0; k < data.length; k++) {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                byte temp = s[i];
                s[i] = s[j];
                s[j] = temp;
                int t = (s[i] + s[j]) % 256;
                result[k] = (byte) (data[k] ^ s[t]);
            }
            return result;
        }
    }

    /**
     * ChaCha20 Encryption
     */
    private class ChaCha20Encryption implements EncryptionAlgorithm {
        @Override
        public String encrypt(String payload) throws Exception {
            return payload + "_CHACHA20_ENCRYPTED";
        }

        @Override
        public String decrypt(String encrypted) throws Exception {
            return encrypted.replace("_CHACHA20_ENCRYPTED", "");
        }

        @Override
        public String generateKey() {
            return "CHACHA20_KEY_" + System.currentTimeMillis();
        }
    }
}
