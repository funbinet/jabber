package com.jabber.jabber.modules.crypto;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;

/**
 * SecureCommModule - Secure encrypted communication channel
 * Provides TLS-like secure communication over raw sockets and other protocols
 */
public class SecureCommModule {
    
    private CryptoOpsModule cryptoOps;
    private Map<String, SecureChannel> channels;
    private Map<String, ChannelContext> channelContexts;
    private ExecutorService executor;
    private SecureRandom random;

    /**
     * Channel Type
     */
    public enum ChannelType {
        TCP, UDP, HTTP, SMTP, DNS, WEBSOCKET, CUSTOM
    }

    /**
     * Message Type
     */
    public enum MessageType {
        HANDSHAKE, KEY_EXCHANGE, ENCRYPTED_DATA, AUTHENTICATION, HEARTBEAT, CLOSE
    }

    /**
     * Secure Channel - Encrypted communication channel
     */
    public static class SecureChannel {
        public String channelId;
        public ChannelType channelType;
        public String remoteAddress;
        public int remotePort;
        public boolean established;
        public long createdTime;
        public long lastActivityTime;
        public int messageCount;
        public Map<String, Object> metadata;

        public SecureChannel(String channelId, ChannelType type, String address, int port) {
            this.channelId = channelId;
            this.channelType = type;
            this.remoteAddress = address;
            this.remotePort = port;
            this.established = false;
            this.createdTime = System.currentTimeMillis();
            this.lastActivityTime = System.currentTimeMillis();
            this.messageCount = 0;
            this.metadata = new ConcurrentHashMap<>();
        }

        public long getAge() {
            return System.currentTimeMillis() - createdTime;
        }

        public long getIdleTime() {
            return System.currentTimeMillis() - lastActivityTime;
        }

        public void recordActivity() {
            this.lastActivityTime = System.currentTimeMillis();
            this.messageCount++;
        }
    }

    /**
     * Channel Context - Encryption context for channel
     */
    public static class ChannelContext {
        public String contextId;
        public String channelId;
        public CryptoOpsModule.Algorithm algorithm;
        public byte[] sessionKey;
        public byte[] macKey;
        public long sequenceNumber;
        public boolean authenticated;
        public String peerIdentity;

        public ChannelContext(String contextId, String channelId) {
            this.contextId = contextId;
            this.channelId = channelId;
            this.sequenceNumber = 0;
            this.authenticated = false;
        }

        public long incrementSequence() {
            return ++sequenceNumber;
        }
    }

    /**
     * Encrypted Message
     */
    public static class EncryptedMessage {
        public MessageType messageType;
        public byte[] ciphertext;
        public byte[] mac;
        public byte[] iv;
        public long sequenceNumber;
        public long timestamp;
        public Map<String, String> headers;

        public EncryptedMessage(MessageType type) {
            this.messageType = type;
            this.timestamp = System.currentTimeMillis();
            this.headers = new HashMap<>();
        }

        public byte[] serialize() throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            
            dos.writeByte(messageType.ordinal());
            dos.writeLong(sequenceNumber);
            dos.writeLong(timestamp);
            dos.writeInt(ciphertext.length);
            dos.write(ciphertext);
            dos.writeInt(mac.length);
            dos.write(mac);
            dos.writeInt(iv != null ? iv.length : 0);
            if (iv != null) dos.write(iv);
            
            return baos.toByteArray();
        }

        public static EncryptedMessage deserialize(byte[] data) throws IOException {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            DataInputStream dis = new DataInputStream(bais);
            
            EncryptedMessage msg = new EncryptedMessage(
                MessageType.values()[dis.readByte()]
            );
            msg.sequenceNumber = dis.readLong();
            msg.timestamp = dis.readLong();
            
            int ctLen = dis.readInt();
            msg.ciphertext = new byte[ctLen];
            dis.readFully(msg.ciphertext);
            
            int macLen = dis.readInt();
            msg.mac = new byte[macLen];
            dis.readFully(msg.mac);
            
            int ivLen = dis.readInt();
            if (ivLen > 0) {
                msg.iv = new byte[ivLen];
                dis.readFully(msg.iv);
            }
            
            return msg;
        }
    }

    /**
     * Constructor
     */
    public SecureCommModule(CryptoOpsModule cryptoOps) {
        this.cryptoOps = cryptoOps;
        this.channels = new ConcurrentHashMap<>();
        this.channelContexts = new ConcurrentHashMap<>();
        this.executor = Executors.newFixedThreadPool(10);
        this.random = new SecureRandom();
    }

    // =========================== CHANNEL SETUP ===========================

    /**
     * Create secure channel
     */
    public SecureChannel createSecureChannel(ChannelType type, String address, int port) throws Exception {
        String channelId = "CH_" + cryptoOps.generateRandomString(16);
        SecureChannel channel = new SecureChannel(channelId, type, address, port);
        
        channels.put(channelId, channel);
        
        // Create channel context
        String contextId = "CTX_" + cryptoOps.generateRandomString(16);
        ChannelContext context = new ChannelContext(contextId, channelId);
        context.algorithm = CryptoOpsModule.Algorithm.AES_256_GCM;
        channelContexts.put(channelId, context);
        
        System.out.println("[SecureComm] Channel created: " + channelId);
        return channel;
    }

    /**
     * Establish secure channel (perform handshake)
     */
    public boolean establishSecureChannel(SecureChannel channel) throws Exception {
        ChannelContext context = channelContexts.get(channel.channelId);
        if (context == null) {
            return false;
        }

        // Generate session key
        context.sessionKey = cryptoOps.generateRandomBytes(32);
        context.macKey = cryptoOps.generateRandomBytes(32);
        
        // Send handshake message
        byte[] handshakeData = cryptoOps.generateRandomBytes(64);
        EncryptedMessage handshake = new EncryptedMessage(MessageType.HANDSHAKE);
        handshake.ciphertext = handshakeData;
        handshake.sequenceNumber = context.incrementSequence();
        handshake.mac = computeMAC(handshakeData, context);
        
        // In real implementation, send over network
        channel.established = true;
        channel.recordActivity();
        
        System.out.println("[SecureComm] Channel established: " + channel.channelId);
        return true;
    }

    /**
     * Close secure channel
     */
    public boolean closeSecureChannel(String channelId) {
        SecureChannel channel = channels.get(channelId);
        if (channel == null) {
            return false;
        }

        try {
            ChannelContext context = channelContexts.get(channelId);
            
            // Send close message
            EncryptedMessage closeMsg = new EncryptedMessage(MessageType.CLOSE);
            closeMsg.sequenceNumber = context.incrementSequence();
            
            // Remove from caches
            channels.remove(channelId);
            channelContexts.remove(channelId);
            
            System.out.println("[SecureComm] Channel closed: " + channelId);
            return true;
        } catch (Exception e) {
            System.out.println("[SecureComm] Close error: " + e.getMessage());
            return false;
        }
    }

    // =========================== MESSAGE ENCRYPTION ===========================

    /**
     * Encrypt message for channel
     */
    public EncryptedMessage encryptMessage(String plaintext, String channelId, MessageType msgType) throws Exception {
        SecureChannel channel = channels.get(channelId);
        ChannelContext context = channelContexts.get(channelId);
        
        if (channel == null || context == null) {
            throw new IllegalArgumentException("Invalid channel: " + channelId);
        }

        EncryptedMessage msg = new EncryptedMessage(msgType);
        
        // Add headers
        msg.headers.put("channelId", channelId);
        msg.headers.put("timestamp", String.valueOf(System.currentTimeMillis()));
        
        // Encrypt message
        byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        msg.iv = cryptoOps.generateRandomBytes(16);
        msg.ciphertext = cryptoOps.encryptSymmetricData(plainBytes, 
            new javax.crypto.spec.SecretKeySpec(context.sessionKey, 0, context.sessionKey.length, "AES"),
            context.algorithm);
        
        // Compute MAC
        msg.mac = computeMAC(msg.ciphertext, context);
        msg.sequenceNumber = context.incrementSequence();
        
        channel.recordActivity();
        return msg;
    }

    /**
     * Decrypt message from channel
     */
    public String decryptMessage(EncryptedMessage encryptedMsg, String channelId) throws Exception {
        SecureChannel channel = channels.get(channelId);
        ChannelContext context = channelContexts.get(channelId);
        
        if (channel == null || context == null) {
            throw new IllegalArgumentException("Invalid channel: " + channelId);
        }

        // Verify MAC
        byte[] expectedMac = computeMAC(encryptedMsg.ciphertext, context);
        if (!Arrays.equals(expectedMac, encryptedMsg.mac)) {
            throw new SecurityException("MAC verification failed");
        }

        // Verify sequence number
        if (encryptedMsg.sequenceNumber <= context.sequenceNumber) {
            throw new SecurityException("Sequence number mismatch");
        }
        context.sequenceNumber = encryptedMsg.sequenceNumber;

        // Decrypt
        byte[] plainBytes = cryptoOps.decryptSymmetricData(encryptedMsg.ciphertext,
            new javax.crypto.spec.SecretKeySpec(context.sessionKey, 0, context.sessionKey.length, "AES"),
            context.algorithm);
        
        channel.recordActivity();
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    // =========================== AUTHENTICATION ===========================

    /**
     * Authenticate peer
     */
    public boolean authenticatePeer(String channelId, String credentials) throws Exception {
        ChannelContext context = channelContexts.get(channelId);
        if (context == null) {
            return false;
        }

        // Verify credentials (simplified)
        byte[] credentialHash = cryptoOps.hashSHA256(credentials);
        byte[] expectedHash = cryptoOps.hashSHA256("valid_credential");
        
        if (Arrays.equals(credentialHash, expectedHash)) {
            context.authenticated = true;
            context.peerIdentity = "peer_" + cryptoOps.generateRandomString(8);
            System.out.println("[SecureComm] Peer authenticated: " + context.peerIdentity);
            return true;
        }
        
        return false;
    }

    /**
     * Check if channel is authenticated
     */
    public boolean isAuthenticated(String channelId) {
        ChannelContext context = channelContexts.get(channelId);
        return context != null && context.authenticated;
    }

    // =========================== COMPRESSION ===========================

    /**
     * Compress plaintext before encryption (optional)
     */
    public byte[] compressData(String plaintext) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        java.util.zip.GZIPOutputStream gos = new java.util.zip.GZIPOutputStream(baos);
        gos.write(plaintext.getBytes(StandardCharsets.UTF_8));
        gos.close();
        return baos.toByteArray();
    }

    /**
     * Decompress after decryption (optional)
     */
    public String decompressData(byte[] compressed) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
        java.util.zip.GZIPInputStream gis = new java.util.zip.GZIPInputStream(bais);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        byte[] buffer = new byte[1024];
        int len;
        while ((len = gis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        
        gis.close();
        return baos.toString(StandardCharsets.UTF_8);
    }

    // =========================== OBFUSCATION ===========================

    /**
     * Obfuscate encrypted message (stealth)
     */
    public byte[] obfuscateMessage(byte[] encryptedData) {
        // Add random padding and header
        byte[] padding = cryptoOps.generateRandomBytes(random.nextInt(64) + 32);
        byte[] fakeHeader = new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(fakeHeader);
            baos.write(encryptedData);
            baos.write(padding);
        } catch (IOException e) {
            // Should not happen with ByteArrayOutputStream
        }
        
        return baos.toByteArray();
    }

    /**
     * De-obfuscate message
     */
    public byte[] deobfuscateMessage(byte[] obfuscatedData) {
        // Remove fake header and padding (simplified)
        if (obfuscatedData.length > 36) {
            return Arrays.copyOfRange(obfuscatedData, 4, obfuscatedData.length - 32);
        }
        return obfuscatedData;
    }

    // =========================== UTILITY METHODS ===========================

    /**
     * Compute MAC (HMAC-SHA256)
     */
    private byte[] computeMAC(byte[] data, ChannelContext context) throws Exception {
        // Use session key for now (should use dedicated MAC key in production)
        Mac mac = Mac.getInstance("HmacSHA256");
        javax.crypto.spec.SecretKeySpec keySpec = 
            new javax.crypto.spec.SecretKeySpec(context.macKey, 0, context.macKey.length, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    /**
     * Get channel info
     */
    public Map<String, Object> getChannelInfo(String channelId) {
        SecureChannel channel = channels.get(channelId);
        if (channel == null) {
            return null;
        }

        Map<String, Object> info = new HashMap<>();
        info.put("channelId", channel.channelId);
        info.put("type", channel.channelType);
        info.put("remote", channel.remoteAddress + ":" + channel.remotePort);
        info.put("established", channel.established);
        info.put("created", channel.createdTime);
        info.put("age", channel.getAge() + "ms");
        info.put("idle", channel.getIdleTime() + "ms");
        info.put("messageCount", channel.messageCount);
        
        ChannelContext context = channelContexts.get(channelId);
        if (context != null) {
            info.put("authenticated", context.authenticated);
            info.put("sequenceNumber", context.sequenceNumber);
            info.put("algorithm", context.algorithm);
        }
        
        return info;
    }

    /**
     * Get all active channels
     */
    public List<String> getActiveChannels() {
        return new ArrayList<>(channels.keySet());
    }

    /**
     * Get channel count
     */
    public int getChannelCount() {
        return channels.size();
    }

    /**
     * Close all channels
     */
    public void closeAllChannels() {
        List<String> channelIds = new ArrayList<>(channels.keySet());
        for (String channelId : channelIds) {
            closeSecureChannel(channelId);
        }
        System.out.println("[SecureComm] All channels closed");
    }

    /**
     * Shutdown module
     */
    public void shutdown() {
        closeAllChannels();
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
        System.out.println("[SecureComm] Module shutdown complete");
    }

    /**
     * Main - Test secure communication
     */
    public static void main(String[] args) {
        try {
            CryptoOpsModule cryptoOps = new CryptoOpsModule();
            SecureCommModule secureComm = new SecureCommModule(cryptoOps);

            System.out.println("[SecureComm] Creating secure channel...");
            SecureChannel channel = secureComm.createSecureChannel(
                ChannelType.TCP, "192.168.1.100", 4444
            );

            System.out.println("[SecureComm] Establishing channel...");
            secureComm.establishSecureChannel(channel);

            System.out.println("\n[SecureComm] Testing encryption/decryption...");
            String message = "Secret message for C2";
            EncryptedMessage encrypted = secureComm.encryptMessage(message, channel.channelId, 
                MessageType.ENCRYPTED_DATA);
            String decrypted = secureComm.decryptMessage(encrypted, channel.channelId);
            System.out.println("[SecureComm] Original: " + message);
            System.out.println("[SecureComm] Decrypted: " + decrypted);

            System.out.println("\n[SecureComm] Testing authentication...");
            secureComm.authenticatePeer(channel.channelId, "valid_credential");
            System.out.println("[SecureComm] Authenticated: " + 
                secureComm.isAuthenticated(channel.channelId));

            System.out.println("\n[SecureComm] Channel info:");
            secureComm.getChannelInfo(channel.channelId).forEach((k, v) -> 
                System.out.println("  " + k + ": " + v)
            );

            System.out.println("\nActive channels: " + secureComm.getChannelCount());

            secureComm.shutdown();
            cryptoOps.shutdown();
        } catch (Exception e) {
            System.out.println("[SecureComm] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
