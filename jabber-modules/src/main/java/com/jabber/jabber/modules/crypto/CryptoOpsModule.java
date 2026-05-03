package com.jabber.jabber.modules.crypto;

import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * CryptoOpsModule - Comprehensive cryptographic operations
 * Provides symmetric/asymmetric encryption, key management, certificates, and secure communications
 */
public class CryptoOpsModule {
    
    private KeyStore keyStore;
    private Map<String, Key> keyCache;
    private Map<String, CertificateInfo> certCache;
    private SecureRandom secureRandom;
    private DateTimeFormatter dateFormat;
    private Map<String, Long> keyRotationSchedule;
    private ScheduledExecutorService asyncExecutor;

    /**
     * Encryption Algorithm Support
     */
    public enum Algorithm {
        AES_128_CBC, AES_192_CBC, AES_256_CBC, AES_256_GCM,
        CHACHA20, CHACHA20_POLY1305,
        RSA_2048, RSA_3072, RSA_4096,
        ECC_P256, ECC_P384, ECC_P521,
        BLOWFISH, TWOFISH, SERPENT
    }

    /**
     * Key Type
     */
    public enum KeyType {
        SYMMETRIC, ASYMMETRIC, HMAC, MASTER_KEY, SESSION_KEY
    }

    /**
     * Key Material - Encrypted key storage
     */
    public static class KeyMaterial {
        public String keyId;
        public KeyType keyType;
        public Algorithm algorithm;
        public byte[] encryptedKey;
        public byte[] salt;
        public long createdTime;
        public long expiryTime;
        public long rotationTime;
        public Map<String, String> metadata;
        public boolean isActive;

        public KeyMaterial(String keyId, KeyType keyType, Algorithm algorithm) {
            this.keyId = keyId;
            this.keyType = keyType;
            this.algorithm = algorithm;
            this.createdTime = System.currentTimeMillis();
            this.metadata = new ConcurrentHashMap<>();
            this.isActive = true;
        }

        public boolean isExpired() {
            return expiryTime > 0 && System.currentTimeMillis() > expiryTime;
        }

        public boolean needsRotation() {
            return rotationTime > 0 && System.currentTimeMillis() > rotationTime;
        }
    }

    /**
     * Certificate Information
     */
    public static class CertificateInfo {
        public String certId;
        public X509Certificate cert;
        public PrivateKey privateKey;
        public long validFrom;
        public long validUntil;
        public String issuer;
        public String subject;
        public String fingerprint;
        public boolean trusted;

        public CertificateInfo(String certId) {
            this.certId = certId;
        }

        public boolean isValid() {
            long now = System.currentTimeMillis();
            return now >= validFrom && now <= validUntil;
        }

        public long getTimeUntilExpiry() {
            return validUntil - System.currentTimeMillis();
        }
    }

    /**
     * Crypto Context - Session-specific encryption context
     */
    public static class CryptoContext {
        public String contextId;
        public Algorithm algorithm;
        public byte[] sessionKey;
        public byte[] iv;
        public byte[] salt;
        public long createdTime;
        public long lastUsedTime;
        public long expiryTime;
        public int messageCount;

        public CryptoContext(String contextId, Algorithm algorithm) {
            this.contextId = contextId;
            this.algorithm = algorithm;
            this.createdTime = System.currentTimeMillis();
            this.lastUsedTime = System.currentTimeMillis();
            this.messageCount = 0;
        }

        public boolean isExpired() {
            return expiryTime > 0 && System.currentTimeMillis() > expiryTime;
        }

        public void recordUsage() {
            this.lastUsedTime = System.currentTimeMillis();
            this.messageCount++;
        }

        public long getIdleTime() {
            return System.currentTimeMillis() - lastUsedTime;
        }
    }

    /**
     * Constructor
     */
    public CryptoOpsModule() throws Exception {
        this.keyCache = new ConcurrentHashMap<>();
        this.certCache = new ConcurrentHashMap<>();
        this.secureRandom = new SecureRandom();
        this.dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        this.keyRotationSchedule = new ConcurrentHashMap<>();
        this.asyncExecutor = Executors.newScheduledThreadPool(5);
        
        // Initialize KeyStore
        initializeKeyStore();
    }

    /**
     * Initialize KeyStore
     */
    private void initializeKeyStore() throws Exception {
        keyStore = KeyStore.getInstance("JCEKS");
        try {
            keyStore.load(null, null); // Initialize empty keystore
        } catch (IOException e) {
            // First time initialization
            keyStore.load(null, "masterpassword".toCharArray());
        }
    }

    // =========================== SYMMETRIC ENCRYPTION ===========================

    /**
     * Encrypt data with symmetric encryption
     */
    public byte[] encryptSymmetric(String plaintext, String keyId, Algorithm algorithm) throws Exception {
        Key key = getOrGenerateKey(keyId, algorithm);
        return encryptSymmetricData(plaintext.getBytes(StandardCharsets.UTF_8), key, algorithm);
    }

    /**
     * Encrypt symmetric data (bytes)
     */
    public byte[] encryptSymmetricData(byte[] data, Key key, Algorithm algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(getAlgorithmSpec(algorithm));
        
        // Generate IV for modes that need it
        byte[] iv = null;
        if (algorithm.toString().contains("CBC") || algorithm.toString().contains("GCM")) {
            iv = generateIV(cipher.getBlockSize());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }

        byte[] encrypted = cipher.doFinal(data);
        
        // Return IV + encrypted data
        if (iv != null) {
            return concatenateByteArrays(iv, encrypted);
        }
        return encrypted;
    }

    /**
     * Decrypt symmetric data
     */
    public String decryptSymmetric(byte[] ciphertext, String keyId, Algorithm algorithm) throws Exception {
        Key key = getOrGenerateKey(keyId, algorithm);
        byte[] plaintext = decryptSymmetricData(ciphertext, key, algorithm);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt symmetric data (bytes)
     */
    public byte[] decryptSymmetricData(byte[] ciphertext, Key key, Algorithm algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(getAlgorithmSpec(algorithm));
        
        byte[] dataToDecrypt = ciphertext;
        byte[] iv = null;

        // Extract IV if applicable
        if (algorithm.toString().contains("CBC") || algorithm.toString().contains("GCM")) {
            int ivSize = 16; // Standard AES block size
            iv = Arrays.copyOf(ciphertext, ivSize);
            dataToDecrypt = Arrays.copyOfRange(ciphertext, ivSize, ciphertext.length);
            
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }

        return cipher.doFinal(dataToDecrypt);
    }

    // =========================== ASYMMETRIC ENCRYPTION ===========================

    /**
     * Encrypt with RSA public key
     */
    public byte[] encryptRSA(String plaintext, String keyId) throws Exception {
        KeyPair keyPair = getOrGenerateKeyPair(keyId, Algorithm.RSA_2048);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypt with RSA private key
     */
    public String decryptRSA(byte[] ciphertext, String keyId) throws Exception {
        KeyPair keyPair = getOrGenerateKeyPair(keyId, Algorithm.RSA_2048);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Generate RSA signature
     */
    public byte[] signData(byte[] data, String keyId) throws Exception {
        KeyPair keyPair = getOrGenerateKeyPair(keyId, Algorithm.RSA_2048);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verify RSA signature
     */
    public boolean verifySignature(byte[] data, byte[] sig, String keyId) throws Exception {
        KeyPair keyPair = getOrGenerateKeyPair(keyId, Algorithm.RSA_2048);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(keyPair.getPublic());
        signature.update(data);
        return signature.verify(sig);
    }

    // =========================== KEY MANAGEMENT ===========================

    /**
     * Get or generate key
     */
    public Key getOrGenerateKey(String keyId, Algorithm algorithm) throws Exception {
        if (keyCache.containsKey(keyId)) {
            return keyCache.get(keyId);
        }

        Key key = generateSymmetricKey(algorithm);
        keyCache.put(keyId, key);
        
        // Store in keystore
        storeKeyInKeyStore(keyId, key, algorithm);
        
        return key;
    }

    /**
     * Generate symmetric key
     */
    public Key generateSymmetricKey(Algorithm algorithm) throws Exception {
        int keySize = getKeySizeForAlgorithm(algorithm);
        
        switch (algorithm) {
            case AES_128_CBC:
            case AES_192_CBC:
            case AES_256_CBC:
            case AES_256_GCM:
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(keySize, secureRandom);
                return keyGen.generateKey();
            
            case CHACHA20:
            case CHACHA20_POLY1305:
                keyGen = KeyGenerator.getInstance("ChaCha20");
                keyGen.init(256, secureRandom);
                return keyGen.generateKey();
            
            case BLOWFISH:
                keyGen = KeyGenerator.getInstance("Blowfish");
                keyGen.init(128, secureRandom);
                return keyGen.generateKey();
            
            default:
                throw new InvalidParameterException("Unsupported algorithm: " + algorithm);
        }
    }

    /**
     * Get or generate key pair (asymmetric)
     */
    public KeyPair getOrGenerateKeyPair(String keyId, Algorithm algorithm) throws Exception {
        // Check cache first
        if (keyCache.containsKey(keyId + "_public")) {
            PublicKey pub = (PublicKey) keyCache.get(keyId + "_public");
            PrivateKey priv = (PrivateKey) keyCache.get(keyId + "_private");
            return new KeyPair(pub, priv);
        }

        KeyPair keyPair = generateKeyPair(algorithm);
        keyCache.put(keyId + "_public", keyPair.getPublic());
        keyCache.put(keyId + "_private", keyPair.getPrivate());
        
        return keyPair;
    }

    /**
     * Generate key pair
     */
    public KeyPair generateKeyPair(Algorithm algorithm) throws Exception {
        KeyPairGenerator keyGen;
        int keySize = getKeySizeForAlgorithm(algorithm);

        switch (algorithm) {
            case RSA_2048:
            case RSA_3072:
            case RSA_4096:
                keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(keySize, secureRandom);
                return keyGen.generateKeyPair();
            
            case ECC_P256:
            case ECC_P384:
            case ECC_P521:
                keyGen = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec ecSpec = getECParameterSpec(algorithm);
                keyGen.initialize(ecSpec, secureRandom);
                return keyGen.generateKeyPair();
            
            default:
                throw new InvalidParameterException("Unsupported key pair algorithm: " + algorithm);
        }
    }

    /**
     * Rotate key
     */
    public synchronized boolean rotateKey(String keyId) throws Exception {
        // Generate new key
        Algorithm algorithm = determineAlgorithm(keyId);
        Key newKey = generateSymmetricKey(algorithm);
        
        // Mark old key as inactive
        keyCache.put(keyId + "_old", keyCache.get(keyId));
        
        // Install new key
        keyCache.put(keyId, newKey);
        storeKeyInKeyStore(keyId, newKey, algorithm);
        
        System.out.println("[CryptoOps] Key rotated: " + keyId);
        return true;
    }

    /**
     * Schedule key rotation
     */
    public void scheduleKeyRotation(String keyId, long intervalMs) {
        keyRotationSchedule.put(keyId, System.currentTimeMillis() + intervalMs);
        
        asyncExecutor.schedule(() -> {
            try {
                rotateKey(keyId);
                scheduleKeyRotation(keyId, intervalMs);
            } catch (Exception e) {
                System.out.println("[CryptoOps] Key rotation failed: " + e.getMessage());
            }
        }, intervalMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Get key material for export/backup
     */
    public KeyMaterial exportKeyMaterial(String keyId, Algorithm algorithm) throws Exception {
        Key key = getOrGenerateKey(keyId, algorithm);
        
        KeyMaterial material = new KeyMaterial(keyId, KeyType.SYMMETRIC, algorithm);
        material.salt = generateSalt(16);
        
        // Encrypt key before export
        byte[] keyBytes = key.getEncoded();
        material.encryptedKey = encryptWithMasterKey(keyBytes, material.salt);
        material.expiryTime = System.currentTimeMillis() + (365 * 24 * 60 * 60 * 1000L); // 1 year
        material.rotationTime = System.currentTimeMillis() + (90 * 24 * 60 * 60 * 1000L);  // 90 days
        
        return material;
    }

    /**
     * Import key material
     */
    public boolean importKeyMaterial(KeyMaterial material) throws Exception {
        try {
            byte[] keyBytes = decryptWithMasterKey(material.encryptedKey, material.salt);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("RAW");
            SecretKey key = factory.generateSecret(new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES"));
            
            keyCache.put(material.keyId, key);
            storeKeyInKeyStore(material.keyId, key, material.algorithm);
            
            System.out.println("[CryptoOps] Imported key: " + material.keyId);
            return true;
        } catch (Exception e) {
            System.out.println("[CryptoOps] Import failed: " + e.getMessage());
            return false;
        }
    }

    // =========================== HASHING & HMAC ===========================

    /**
     * Generate SHA-256 hash
     */
    public byte[] hashSHA256(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate SHA-512 hash
     */
    public byte[] hashSHA512(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return digest.digest(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate HMAC-SHA256
     */
    public byte[] hmacSHA256(String data, String keyId) throws Exception {
        Key key = getOrGenerateKey(keyId, Algorithm.AES_256_CBC);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate HMAC-SHA512
     */
    public byte[] hmacSHA512(String data, String keyId) throws Exception {
        Key key = getOrGenerateKey(keyId, Algorithm.AES_256_CBC);
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(key);
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    // =========================== CERTIFICATE OPERATIONS ===========================

    /**
     * Generate self-signed certificate
     */
    public CertificateInfo generateSelfSignedCertificate(String certId, String subjectDN, 
                                                         int validityDays) throws Exception {
        // Generate key pair
        KeyPair keyPair = generateKeyPair(Algorithm.RSA_2048);
        
        // Create certificate
        java.security.cert.Certificate cert = generateSelfSignedCert(
            keyPair.getPrivate(),
            keyPair.getPublic(),
            subjectDN,
            validityDays
        );

        CertificateInfo certInfo = new CertificateInfo(certId);
        certInfo.cert = (X509Certificate) cert;
        certInfo.privateKey = keyPair.getPrivate();
        certInfo.subject = subjectDN;
        certInfo.validFrom = System.currentTimeMillis();
        certInfo.validUntil = System.currentTimeMillis() + (validityDays * 24 * 60 * 60 * 1000L);
        
        // Calculate fingerprint
        certInfo.fingerprint = calculateCertFingerprint(certInfo.cert);
        certInfo.trusted = false;
        
        certCache.put(certId, certInfo);
        return certInfo;
    }

    /**
     * Get certificate info
     */
    public CertificateInfo getCertificateInfo(String certId) {
        return certCache.get(certId);
    }

    /**
     * Verify certificate chain
     */
    public boolean verifyCertificate(CertificateInfo certInfo) throws Exception {
        if (!certInfo.isValid()) {
            System.out.println("[CryptoOps] Certificate expired: " + certInfo.certId);
            return false;
        }

        try {
            certInfo.cert.checkValidity();
            return true;
        } catch (CertificateException e) {
            System.out.println("[CryptoOps] Certificate verification failed: " + e.getMessage());
            return false;
        }
    }

    // =========================== KEY EXCHANGE (ECDH) ===========================

    /**
     * Generate ECDH key agreement
     */
    public byte[] performECDHKeyExchange(String clientKeyId, PublicKey serverPublicKey) throws Exception {
        KeyPair clientKeyPair = getOrGenerateKeyPair(clientKeyId, Algorithm.ECC_P256);
        
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(clientKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        
        return keyAgreement.generateSecret();
    }

    // =========================== RANDOM GENERATION ===========================

    /**
     * Generate secure random bytes
     */
    public byte[] generateRandomBytes(int length) {
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Generate initialization vector (IV)
     */
    public byte[] generateIV(int blockSize) {
        return generateRandomBytes(blockSize);
    }

    /**
     * Generate salt
     */
    public byte[] generateSalt(int length) {
        return generateRandomBytes(length);
    }

    /**
     * Generate secure random string
     */
    public String generateRandomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(secureRandom.nextInt(chars.length())));
        }
        return sb.toString();
    }

    // =========================== UTILITY METHODS ===========================

    /**
     * Get algorithm specification string
     */
    private String getAlgorithmSpec(Algorithm algorithm) {
        switch (algorithm) {
            case AES_128_CBC:
            case AES_192_CBC:
            case AES_256_CBC:
                return "AES/CBC/PKCS5Padding";
            case AES_256_GCM:
                return "AES/GCM/NoPadding";
            case CHACHA20:
                return "ChaCha20";
            case CHACHA20_POLY1305:
                return "ChaCha20-Poly1305";
            case BLOWFISH:
                return "Blowfish/CBC/PKCS5Padding";
            default:
                return "AES/CBC/PKCS5Padding";
        }
    }

    /**
     * Get key size for algorithm
     */
    private int getKeySizeForAlgorithm(Algorithm algorithm) {
        switch (algorithm) {
            case AES_128_CBC:
                return 128;
            case AES_192_CBC:
                return 192;
            case AES_256_CBC:
            case AES_256_GCM:
                return 256;
            case RSA_2048:
                return 2048;
            case RSA_3072:
                return 3072;
            case RSA_4096:
                return 4096;
            case CHACHA20:
                return 256;
            case BLOWFISH:
                return 128;
            default:
                return 256;
        }
    }

    /**
     * Get EC parameter spec
     */
    private ECGenParameterSpec getECParameterSpec(Algorithm algorithm) {
        switch (algorithm) {
            case ECC_P256:
                return new ECGenParameterSpec("secp256r1");
            case ECC_P384:
                return new ECGenParameterSpec("secp384r1");
            case ECC_P521:
                return new ECGenParameterSpec("secp521r1");
            default:
                return new ECGenParameterSpec("secp256r1");
        }
    }

    /**
     * Store key in keystore
     */
    private void storeKeyInKeyStore(String keyId, Key key, Algorithm algorithm) throws Exception {
        try {
            if (key instanceof SecretKey) {
                keyStore.setKeyEntry(keyId, key, "keypassword".toCharArray(), null);
                // Save keystore
                try (FileOutputStream fos = new FileOutputStream("/tmp/jabber.keystore")) {
                    keyStore.store(fos, "keystorepassword".toCharArray());
                }
            }
        } catch (Exception e) {
            System.out.println("[CryptoOps] KeyStore store error: " + e.getMessage());
        }
    }

    /**
     * Concatenate byte arrays
     */
    private byte[] concatenateByteArrays(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

    /**
     * Encrypt with master key
     */
    private byte[] encryptWithMasterKey(byte[] data, byte[] salt) throws Exception {
        Key masterKey = getOrGenerateKey("MASTER_KEY", Algorithm.AES_256_CBC);
        return encryptSymmetricData(data, masterKey, Algorithm.AES_256_CBC);
    }

    /**
     * Decrypt with master key
     */
    private byte[] decryptWithMasterKey(byte[] ciphertext, byte[] salt) throws Exception {
        Key masterKey = getOrGenerateKey("MASTER_KEY", Algorithm.AES_256_CBC);
        return decryptSymmetricData(ciphertext, masterKey, Algorithm.AES_256_CBC);
    }

    /**
     * Generate self-signed certificate (helper)
     */
    private java.security.cert.Certificate generateSelfSignedCert(PrivateKey privateKey, 
                                                                   PublicKey publicKey,
                                                                   String subjectDN,
                                                                   int validityDays) throws Exception {
        // This is a simplified version - in production use Bouncy Castle or similar
        System.out.println("[CryptoOps] Certificate generation requires BouncyCastle library");
        return null;
    }

    /**
     * Calculate certificate fingerprint
     */
    private String calculateCertFingerprint(X509Certificate cert) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] certBytes = cert.getEncoded();
        byte[] fingerprint = digest.digest(certBytes);
        return bytesToHex(fingerprint);
    }

    /**
     * Determine algorithm from key ID
     */
    private Algorithm determineAlgorithm(String keyId) {
        if (keyId.contains("RSA")) return Algorithm.RSA_2048;
        if (keyId.contains("ECC")) return Algorithm.ECC_P256;
        return Algorithm.AES_256_CBC;
    }

    /**
     * Convert bytes to hex
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Get key cache size
     */
    public int getKeyCacheSize() {
        return keyCache.size();
    }

    /**
     * Get certificate cache size
     */
    public int getCertCacheSize() {
        return certCache.size();
    }

    /**
     * Clear caches
     */
    public void clearCaches() {
        keyCache.clear();
        certCache.clear();
        System.out.println("[CryptoOps] Caches cleared");
    }

    /**
     * Shutdown module
     */
    public void shutdown() {
        asyncExecutor.shutdown();
        try {
            if (!asyncExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                asyncExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            asyncExecutor.shutdownNow();
        }
        clearCaches();
        System.out.println("[CryptoOps] Module shutdown complete");
    }

    /**
     * Get crypto statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("keyCacheSize", getKeyCacheSize());
        stats.put("certCacheSize", getCertCacheSize());
        stats.put("keystoreSize", keyStore != null ? 1 : 0);
        stats.put("supportedAlgorithms", Algorithm.values().length);
        stats.put("timestamp", LocalDateTime.now().format(dateFormat));
        return stats;
    }

    /**
     * Main - Test crypto operations
     */
    public static void main(String[] args) {
        try {
            CryptoOpsModule crypto = new CryptoOpsModule();

            System.out.println("[CryptoOps] Testing symmetric encryption...");
            String plaintext = "Secret message for C2 communication";
            byte[] encrypted = crypto.encryptSymmetric(plaintext, "test-key-1", Algorithm.AES_256_CBC);
            String decrypted = crypto.decryptSymmetric(encrypted, "test-key-1", Algorithm.AES_256_CBC);
            System.out.println("[CryptoOps] Original: " + plaintext);
            System.out.println("[CryptoOps] Decrypted: " + decrypted);

            System.out.println("\n[CryptoOps] Testing RSA encryption...");
            byte[] rsa_encrypted = crypto.encryptRSA("RSA test", "rsa-key-1");
            String rsa_decrypted = crypto.decryptRSA(rsa_encrypted, "rsa-key-1");
            System.out.println("[CryptoOps] RSA Decrypted: " + rsa_decrypted);

            System.out.println("\n[CryptoOps] Testing hashing...");
            byte[] hash = crypto.hashSHA256("test data");
            System.out.println("[CryptoOps] SHA256: " + crypto.bytesToHex(hash).substring(0, 16) + "...");

            System.out.println("\n[CryptoOps] Testing key generation...");
            KeyPair ecc = crypto.generateKeyPair(Algorithm.ECC_P256);
            System.out.println("[CryptoOps] ECC Key Pair generated: " + ecc.getPublic().getAlgorithm());

            System.out.println("\n[CryptoOps] Statistics:");
            crypto.getStatistics().forEach((k, v) -> System.out.println("  " + k + ": " + v));

            crypto.shutdown();
        } catch (Exception e) {
            System.out.println("[CryptoOps] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
