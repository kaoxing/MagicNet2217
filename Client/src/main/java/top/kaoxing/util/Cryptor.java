package top.kaoxing.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.*;

public final class Cryptor {
    private static final int VERSION = 2;
    private static final int SALT_LEN = 16, IV_LEN = 12, TAG_BITS = 128, KEY_BITS = 256;
    private static final int PBKDF2_ITERS = 200_000;
    private static final long ROTATE_MS = 60L * 60L * 1000L;

    private static final SecureRandom RNG = new SecureRandom();

    // 双槽缓存（当前盐/上一盐）
    private static volatile byte[] saltA = random(SALT_LEN), saltB = null;
    private static volatile SecretKey keyA = null, keyB = null;
    private static volatile long nextRotateAt = System.currentTimeMillis() + ROTATE_MS;

    // ThreadLocal Cipher（避免反复 new）
    private static final ThreadLocal<Cipher> ENC = ThreadLocal.withInitial(() -> newCipher());
    private static final ThreadLocal<Cipher> DEC = ThreadLocal.withInitial(() -> newCipher());

    private static Cipher newCipher() {
        try { return Cipher.getInstance("AES/GCM/NoPadding"); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
    private static byte[] random(int n) { byte[] x = new byte[n]; RNG.nextBytes(x); return x; }

    private static void rotateIfNeeded() {
        long now = System.currentTimeMillis();
        if (now >= nextRotateAt) {
            synchronized (Cryptor.class) {
                if (now >= nextRotateAt) {
                    saltB = saltA; keyB = keyA;           // 旧的挪到 B 槽
                    saltA = random(SALT_LEN); keyA = null; // 新盐，待派生
                    nextRotateAt = (now / ROTATE_MS) * ROTATE_MS + ROTATE_MS;
                }
            }
        }
    }

    private static SecretKey derive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, KEY_BITS);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] kb = f.generateSecret(spec).getEncoded();
        SecretKey k = new SecretKeySpec(kb, "AES");
        Arrays.fill(kb, (byte)0);
        return k;
    }

    private static SecretKey keyFor(char[] password, byte[] salt) throws Exception {
        // 命中 A 槽
        byte[] a = saltA; if (a != null && Arrays.equals(salt, a)) {
            SecretKey k = keyA; if (k != null) return k;
            synchronized (Cryptor.class) {
                if (keyA == null) keyA = derive(password, saltA);
                return keyA;
            }
        }
        // 命中 B 槽
        byte[] b = saltB; if (b != null && Arrays.equals(salt, b)) {
            SecretKey k = keyB; if (k != null) return k;
            synchronized (Cryptor.class) {
                if (keyB == null) keyB = derive(password, saltB);
                return keyB;
            }
        }
        // 极端情况：老报文/时钟偏移，临时派生一次（不入缓存，保持简单）
        return derive(password, salt);
    }

    // ===== API =====

    public static byte[] encrypt(byte[] plain, char[] password) {
        try {
            if (plain == null) throw new IllegalArgumentException("null");
            rotateIfNeeded();

            byte[] salt = saltA;          // 当前盐
            if (salt == null) throw new IllegalStateException("saltA null");
            SecretKey key = keyFor(password, salt);

            byte[] iv = random(IV_LEN);

            Cipher c = ENC.get();
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));

            // AAD: [VER|SALT]
            byte[] aad = new byte[1 + SALT_LEN];
            aad[0] = (byte) VERSION;
            System.arraycopy(salt, 0, aad, 1, SALT_LEN);
            c.updateAAD(aad);

            byte[] ct = c.doFinal(plain);

            byte[] out = new byte[1 + SALT_LEN + IV_LEN + ct.length];
            out[0] = (byte) VERSION;
            System.arraycopy(salt, 0, out, 1, SALT_LEN);
            System.arraycopy(iv,   0, out, 1+SALT_LEN, IV_LEN);
            System.arraycopy(ct,   0, out, 1+SALT_LEN+IV_LEN, ct.length);
            return out;
        } catch (Exception e) {
            throw new RuntimeException("encrypt failed", e);
        }
    }

    public static byte[] decrypt(byte[] blob, char[] password) {
        try {
            if (blob == null || blob.length < 1 + SALT_LEN + IV_LEN + 16)
                throw new IllegalArgumentException("short");

            int off = 0;
            int ver = blob[off++] & 0xFF;
            if (ver != VERSION) throw new IllegalArgumentException("ver");

            byte[] salt = Arrays.copyOfRange(blob, off, off+SALT_LEN); off += SALT_LEN;
            byte[] iv   = Arrays.copyOfRange(blob, off, off+IV_LEN);   off += IV_LEN;
            byte[] ct   = Arrays.copyOfRange(blob, off, blob.length);

            SecretKey key = keyFor(password, salt);

            Cipher c = DEC.get();
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));

            byte[] aad = new byte[1 + SALT_LEN];
            aad[0] = (byte) VERSION;
            System.arraycopy(salt, 0, aad, 1, SALT_LEN);
            c.updateAAD(aad);

            return c.doFinal(ct);
        } catch (Exception e) {
            throw new RuntimeException("decrypt failed", e);
        }
    }
}
