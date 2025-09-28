package top.kaoxing;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;

public class Cryptor {
    // ===== 协议 & 参数 =====
    private static final int VERSION = 2;          // 仅 v2
    private static final int SALT_LEN = 16;        // 128-bit salt（明文携带）
    private static final int IV_LEN   = 12;        // 96-bit GCM nonce
    private static final int TAG_LEN_BITS = 128;   // 16字节TAG
    private static final int KEY_LEN_BITS = 256;   // AES-256
    private static final int PBKDF2_ITERS = 200_000;

    // 每小时旋转一次 salt（仅影响发端；收端按报文里的 salt 缓存/派生）
    private static final long ROTATE_MS = 60L * 60L * 1000L;

    // LRU 缓存大小（salt→SecretKey）
    private static final int MAX_CACHE_ENTRIES = 512;

    private static final SecureRandom RNG = new SecureRandom();

    // 部署级固定 pepper（可为空字符串，如需更强可放配置/安全存储）
    private static final byte[] PEPPER = "deploy-pepper-v2".getBytes(StandardCharsets.US_ASCII);

    // ===== 发端：当前小时 salt（进程级，随小时更换） =====
    private static volatile byte[] currentSalt = randomSalt();
    private static final AtomicLong nextRotateAt = new AtomicLong(System.currentTimeMillis() + ROTATE_MS);

    private static byte[] randomSalt() {
        byte[] s = new byte[SALT_LEN];
        RNG.nextBytes(s);
        return s;
    }

    /** 获取当前可用 salt：按小时滚动（线程安全，无锁快路径） */
    private static byte[] getRollingSalt() {
        long now = System.currentTimeMillis();
        long deadline = nextRotateAt.get();
        if (now >= deadline) {
            synchronized (Cryptor.class) {
                if (now >= nextRotateAt.get()) {
                    currentSalt = randomSalt();
                    nextRotateAt.set((now / ROTATE_MS) * ROTATE_MS + ROTATE_MS);
                }
            }
        }
        return currentSalt;
    }

    // ===== LRU 缓存（saltBase64 → SecretKey）=====
    private static final class LruMap<K,V> extends LinkedHashMap<K,V> {
        private final int maxEntries;
        LruMap(int maxEntries) {
            super(16, 0.75f, true);
            this.maxEntries = maxEntries;
        }
        @Override
        protected boolean removeEldestEntry(Map.Entry<K,V> eldest) {
            return size() > maxEntries;
        }
    }
    private static final Map<String, SecretKey> KEY_CACHE = Collections.synchronizedMap(new LruMap<>(MAX_CACHE_ENTRIES));

    private static String b64(byte[] salt) {
        return Base64.getEncoder().encodeToString(salt);
    }

    private static SecretKey deriveAndCache(char[] password, byte[] salt) throws Exception {
        String keyId = b64(salt);
        SecretKey k = KEY_CACHE.get(keyId);
        if (k != null) return k;

        // KDF 输入盐：salt || PEPPER（若不想用pepper，可仅用salt）
        byte[] kdfSalt = new byte[salt.length + PEPPER.length];
        System.arraycopy(salt, 0, kdfSalt, 0, salt.length);
        System.arraycopy(PEPPER, 0, kdfSalt, salt.length, PEPPER.length);

        PBEKeySpec spec = new PBEKeySpec(password, kdfSalt, PBKDF2_ITERS, KEY_LEN_BITS);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        Arrays.fill(kdfSalt, (byte)0);

        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        Arrays.fill(keyBytes, (byte)0);

        KEY_CACHE.put(keyId, key);
        return key;
    }

    // ===== 加密： [VER][SALT][IV][CT+TAG]，AAD = [VER|SALT] =====
    public static byte[] encrypt(byte[] data, String password) {
        try {
            if (data == null) throw new IllegalArgumentException("plaintext is null");

            byte[] salt = getRollingSalt();                   // 每小时更新一次
            SecretKey key = deriveAndCache(password.toCharArray(), salt);

            byte[] iv = new byte[IV_LEN];
            RNG.nextBytes(iv);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BITS, iv);
            c.init(Cipher.ENCRYPT_MODE, key, spec);

            // 认证头（防篡改）
            ByteBuffer aad = ByteBuffer.allocate(1 + SALT_LEN);
            aad.put((byte) VERSION).put(salt);
            c.updateAAD(aad.array());

            byte[] ct = c.doFinal(data);

            ByteBuffer out = ByteBuffer.allocate(1 + SALT_LEN + IV_LEN + ct.length);
            out.put((byte) VERSION).put(salt).put(iv).put(ct);
            return out.array();
        } catch (Exception e) {
            throw new RuntimeException("Encrypt failed", e);
        }
    }

    // ===== 解密：按报文里的 salt 找/算 key；AAD 同步 =====
    public static byte[] decrypt(byte[] blob, String password) {
        try {
            if (blob == null || blob.length < 1 + SALT_LEN + IV_LEN + 16)
                throw new IllegalArgumentException("ciphertext too short/null");

            ByteBuffer in = ByteBuffer.wrap(blob);
            int ver = in.get() & 0xFF;
            if (ver != VERSION) throw new IllegalArgumentException("unsupported version: " + ver);

            byte[] salt = new byte[SALT_LEN];
            in.get(salt);
            byte[] iv = new byte[IV_LEN];
            in.get(iv);
            byte[] ct = new byte[in.remaining()];
            in.get(ct);

            SecretKey key = deriveAndCache(password.toCharArray(), salt);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LEN_BITS, iv);
            c.init(Cipher.DECRYPT_MODE, key, spec);

            ByteBuffer aad = ByteBuffer.allocate(1 + SALT_LEN);
            aad.put((byte) VERSION).put(salt);
            c.updateAAD(aad.array());

            return c.doFinal(ct); // AEADBadTagException → 认证失败
        } catch (Exception e) {
            throw new RuntimeException("Decrypt failed", e);
        }
    }

    // ===== 可选：管理缓存 =====
    public static void clearCache() {
        KEY_CACHE.clear();
    }
    public static int cacheSize() {
        return KEY_CACHE.size();
    }
}
