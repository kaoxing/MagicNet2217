package top.kaoxing;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class ProxyServer {

    // ============================ 会话加密器（与客户端一致） ============================

    static final class SessionCipher {
        private static final byte[] HKDF_INFO = "ss-subkey".getBytes(StandardCharsets.US_ASCII);

        private final SecretKeySpec subKey; // 32B
        private final Cipher enc;
        private final Cipher dec;
        private long sendCounter = 0;       // 96-bit nonce 的低 64 位（示例）

        private SessionCipher(byte[] masterKey, byte[] salt16) throws Exception {
            byte[] sk = hkdf(masterKey, salt16, HKDF_INFO, 32);
            this.subKey = new SecretKeySpec(sk, "AES");
            Arrays.fill(sk, (byte) 0);
            this.enc = Cipher.getInstance("AES/GCM/NoPadding");
            this.dec = Cipher.getInstance("AES/GCM/NoPadding");
        }

        // 服务器握手：读取客户端发来的 salt(16)
        static SessionCipher serverHandshake(SocketChannel ch, String password) throws IOException {
            try {
                byte[] master = masterKeyFromPassword(password);
                byte[] salt = new byte[16];
                readFully(ByteBuffer.wrap(salt), ch);
                return new SessionCipher(master, salt);
            } catch (Exception e) {
                throw new IOException("handshake/session init failed", e);
            }
        }

        // 加密：输出 [12B nonce][cipher|tag]
        byte[] encrypt(byte[] plain) throws Exception {
            byte[] nonce = nextNonce12();
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
            enc.init(Cipher.ENCRYPT_MODE, subKey, spec);
            byte[] ct = enc.doFinal(plain);
            byte[] out = new byte[12 + ct.length];
            System.arraycopy(nonce, 0, out, 0, 12);
            System.arraycopy(ct, 0, out, 12, ct.length);
            return out;
        }

        // 解密：输入含 [12B nonce][cipher|tag]
        byte[] decrypt(byte[] packet) throws Exception {
            if (packet.length < 12 + 16) throw new IllegalArgumentException("packet too short");
            byte[] nonce = Arrays.copyOfRange(packet, 0, 12);
            byte[] ct    = Arrays.copyOfRange(packet, 12, packet.length);
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
            dec.init(Cipher.DECRYPT_MODE, subKey, spec);
            return dec.doFinal(ct);
        }

        private byte[] nextNonce12() {
            byte[] n = new byte[12];
            long x = sendCounter++;
            n[4]  = (byte)(x >>> 56);
            n[5]  = (byte)(x >>> 48);
            n[6]  = (byte)(x >>> 40);
            n[7]  = (byte)(x >>> 32);
            n[8]  = (byte)(x >>> 24);
            n[9]  = (byte)(x >>> 16);
            n[10] = (byte)(x >>> 8);
            n[11] = (byte)(x);
            return n;
        }

        // ---------- HKDF(SHA-1) ----------
        private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
            byte[] prk = hkdfExtract(salt, ikm); // HMAC-SHA1
            return hkdfExpand(prk, info, len);
        }

        private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(salt, "HmacSHA1"));
            return mac.doFinal(ikm); // PRK
        }

        private static byte[] hkdfExpand(byte[] prk, byte[] info, int len) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(prk, "HmacSHA1"));
            byte[] out = new byte[len];
            byte[] t = new byte[0];
            int pos = 0;
            byte counter = 1;
            while (pos < len) {
                mac.reset();
                mac.update(t);
                if (info != null) mac.update(info);
                mac.update(counter);
                t = mac.doFinal();
                int cp = Math.min(t.length, len - pos);
                System.arraycopy(t, 0, out, pos, cp);
                pos += cp;
                counter++;
            }
            return out;
        }

        private static byte[] masterKeyFromPassword(String password) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(password.getBytes(StandardCharsets.UTF_8));
        }
    }

    public static void run() {
        Thread t = Thread.startVirtualThread(() -> {
            try {
                listenTCP();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        try {
            t.join();
        } catch (InterruptedException e) {
            AppLogger.error("Interrupted while waiting for server to start");
        }
    }

    // ============================ TCP 监听 ============================

    static void listenTCP() throws IOException {
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.bind(new InetSocketAddress(Config.SERVER_PORT));
        System.out.println("TCP Server listening on port " + Config.SERVER_PORT);
        while (true) {
            SocketChannel clientChannel = serverSocketChannel.accept();

            clientChannel.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
            clientChannel.setOption(StandardSocketOptions.TCP_NODELAY, true);
            clientChannel.setOption(StandardSocketOptions.SO_SNDBUF, 4 * 1024 * 1024);
            clientChannel.setOption(StandardSocketOptions.SO_RCVBUF, 4 * 1024 * 1024);

            Thread.startVirtualThread(() -> handleTCPClient(clientChannel));
        }
    }

    /**
     * 首帧判别：
     * - 若能按 [ATYP][ADDR][PORT] 精确解析：走 TCP CONNECT。
     * - 否则：按 UDP-over-TCP 处理（首帧即内层UDP帧，FT=0x01）。
     */
    static void handleTCPClient(SocketChannel clientChannel) {
        SessionCipher sess = null;
        try {
            // ===== 会话握手：先读 16B salt，派生 subkey =====
            sess = SessionCipher.serverHandshake(clientChannel, Config.PASSWORD);

            // 读第一帧（[4B len][nonce+ct] -> 解密 first[]）
            byte[] first = readCipherFrame(clientChannel, sess);

            // 尝试当作 CONNECT 目标头
            InetSocketAddress targetAddr = tryParseTargetHeader(first);
            if (targetAddr != null) {
                // ===== CONNECT 模式 =====
                SocketChannel targetChannel = connectTcpTarget(targetAddr);
                SessionCipher finalSess = sess;
                Thread t1 = Thread.startVirtualThread(() -> pumpClientToTarget(clientChannel, targetChannel, finalSess));
                Thread t2 = Thread.startVirtualThread(() -> pumpTargetToClient(targetChannel, clientChannel, finalSess));
                t1.join();
                t2.join();
                closeQuietly(targetChannel);
                return;
            }

            // ===== UDP-over-TCP 模式 =====
            DatagramChannel udp = DatagramChannel.open();
            udp.bind(new InetSocketAddress(0)); // 为该 TCP 连接单独开 UDP 口
            udp.configureBlocking(true);

            // 先处理已读到的第一帧（它是内层 UDP 帧）
            pumpTcpToUdpOnce(udp, first);

            SessionCipher finalSess1 = sess;
            Thread t1 = Thread.startVirtualThread(() -> pumpTcpToUdp(clientChannel, udp, finalSess1));
            Thread t2 = Thread.startVirtualThread(() -> pumpUdpToTcp(udp, clientChannel, finalSess1));
            t1.join();
            t2.join();
            closeQuietly(udp);

        } catch (Exception e) {
            // 可按需打印日志
            // e.printStackTrace();
        } finally {
            closeQuietly(clientChannel);
        }
    }

    // ============================ CONNECT 路径 ============================

    static SocketChannel connectTcpTarget(InetSocketAddress remote) throws IOException {
        SocketChannel target = SocketChannel.open();
        try {
            target.configureBlocking(true);
            target.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
            target.setOption(StandardSocketOptions.TCP_NODELAY, true);
            target.setOption(StandardSocketOptions.SO_SNDBUF, 4 * 1024 * 1024);
            target.setOption(StandardSocketOptions.SO_RCVBUF, 4 * 1024 * 1024);
            target.connect(remote);
            if (!target.isConnected()) throw new IOException("Connect failed to " + remote);
            return target;
        } catch (IOException e) {
            closeQuietly(target);
            throw e;
        }
    }

    // 尝试把 buf 按 [ATYP][ADDR][PORT] 解析；成功返回地址，失败返回 null
    static InetSocketAddress tryParseTargetHeader(byte[] buf) {
        try {
            ByteBuffer b = ByteBuffer.wrap(buf);
            if (b.remaining() < 1 + 2) return null;
            int atyp = b.get() & 0xFF;
            switch (atyp) {
                case 0x01: { // IPv4: 总长必须=1+4+2
                    if (buf.length != 1 + 4 + 2) return null;
                    byte[] ip = new byte[4];
                    b.get(ip);
                    int port = Short.toUnsignedInt(b.getShort());
                    return new InetSocketAddress(java.net.InetAddress.getByAddress(ip), port);
                }
                case 0x03: { // 域名: 总长必须=1+1+len+2
                    if (b.remaining() < 1) return null;
                    int n = b.get() & 0xFF;
                    if (buf.length != 1 + 1 + n + 2) return null;
                    byte[] name = new byte[n];
                    b.get(name);
                    int port = Short.toUnsignedInt(b.getShort());
                    String host = new String(name, StandardCharsets.US_ASCII);
                    return new InetSocketAddress(host, port);
                }
                case 0x04: { // IPv6: 总长必须=1+16+2
                    if (buf.length != 1 + 16 + 2) return null;
                    byte[] ip6 = new byte[16];
                    b.get(ip6);
                    int port = Short.toUnsignedInt(b.getShort());
                    return new InetSocketAddress(java.net.InetAddress.getByAddress(ip6), port);
                }
                default:
                    AppLogger.warning("Client sent unknown ATYP: " + atyp);
                    return null;
            }
        } catch (Exception ignore) {
            return null;
        }
    }

    // C -> SS -> Target
    static void pumpClientToTarget(SocketChannel client, SocketChannel target, SessionCipher sess) {
        try {
            while (true) {
                byte[] plain = readCipherFrame(client, sess);
                if (plain == null || plain.length == 0) break;
                writeFully(target, ByteBuffer.wrap(plain));
            }
        } catch (IOException ignore) {
        } finally {
            safeShutdownOutput(target);
        }
    }

    // Target -> SS -> C
    static void pumpTargetToClient(SocketChannel target, SocketChannel client, SessionCipher sess) {
        final int CHUNK = 64 * 1024;
        ByteBuffer buf = ByteBuffer.allocateDirect(CHUNK);
        try {
            while (true) {
                buf.clear();
                int n = target.read(buf);
                if (n < 0) break;
                if (n == 0) continue;
                buf.flip();
                byte[] plain = new byte[buf.remaining()];
                buf.get(plain);
                writeCipherFrame(client, plain, sess);
            }
        } catch (IOException ignore) {
        } finally {
            safeShutdownOutput(client);
        }
    }

    // ============================ UDP-over-TCP 路径 ============================

    // 处理首帧（已读到的 inner）
    static void pumpTcpToUdpOnce(DatagramChannel udp, byte[] inner) {
        try {
            handleOneInnerFromTcp(udp, inner);
        } catch (Exception ignore) {
        }
    }

    // TCP -> UDP：读外层帧 -> 解密出 inner -> 解析内层UDP帧(FT=0x01) -> 发往目标
    static void pumpTcpToUdp(SocketChannel client, DatagramChannel udp, SessionCipher sess) {
        try {
            while (true) {
                byte[] inner = readCipherFrame(client, sess);
                handleOneInnerFromTcp(udp, inner);
            }
        } catch (IOException ignore) {
        } finally {
            closeQuietly(udp);
        }
    }

    static void handleOneInnerFromTcp(DatagramChannel udp, byte[] inner) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(inner);
        if (bb.remaining() < 1 + 1 + 2) return;
        int ft = bb.get() & 0xFF;
        if (ft != 0x01) return; // 只处理 C->S
        InetSocketAddress target = readAtypAddrPort(bb);
        if (bb.remaining() < 2) return;
        int dlen = Short.toUnsignedInt(bb.getShort());
        if (bb.remaining() < dlen) return;
        byte[] payload = new byte[dlen];
        bb.get(payload);

        udp.send(ByteBuffer.wrap(payload), target);
    }

    // UDP -> TCP：收目标回包 -> inner(FT=0x02) -> 外层加密 -> 回写 TCP
    static void pumpUdpToTcp(DatagramChannel udp, SocketChannel client, SessionCipher sess) {
        ByteBuffer buf = ByteBuffer.allocateDirect(64 * 1024);
        try {
            while (true) {
                buf.clear();
                SocketAddress from = udp.receive(buf);
                if (!(from instanceof InetSocketAddress src)) continue;
                buf.flip();
                if (!buf.hasRemaining()) continue;

                byte[] payload = new byte[buf.remaining()];
                buf.get(payload);

                byte[] inner = buildInnerUdpFrame((byte) 0x02, src, payload);
                writeCipherFrame(client, inner, sess);
            }
        } catch (IOException ignore) {
        } finally {
            closeQuietly(client);
        }
    }

    // 解析 [ATYP][ADDR][PORT]
    static InetSocketAddress readAtypAddrPort(ByteBuffer bb) throws IOException {
        if (bb.remaining() < 1 + 2) throw new IOException("short header");
        int atyp = bb.get() & 0xFF;
        switch (atyp) {
            case 0x01: {
                if (bb.remaining() < 4 + 2) throw new IOException("short ipv4");
                byte[] ip = new byte[4];
                bb.get(ip);
                int port = Short.toUnsignedInt(bb.getShort());
                return new InetSocketAddress(java.net.InetAddress.getByAddress(ip), port);
            }
            case 0x03: {
                int len = bb.get() & 0xFF;
                if (bb.remaining() < len + 2) throw new IOException("short domain");
                byte[] name = new byte[len];
                bb.get(name);
                int port = Short.toUnsignedInt(bb.getShort());
                String host = new String(name, StandardCharsets.UTF_8);
                return new InetSocketAddress(host, port);
            }
            case 0x04: {
                if (bb.remaining() < 16 + 2) throw new IOException("short ipv6");
                byte[] ip = new byte[16];
                bb.get(ip);
                int port = Short.toUnsignedInt(bb.getShort());
                return new InetSocketAddress(java.net.InetAddress.getByAddress(ip), port);
            }
            default:
                throw new IOException("bad ATYP " + atyp);
        }
    }

    // inner 构建：FT + [ATYP][ADDR][PORT] + [2B LEN] + DATA
    static byte[] buildInnerUdpFrame(byte ft, SocketAddress addr, byte[] payload) throws IOException {
        if (!(addr instanceof InetSocketAddress isa)) {
            throw new IOException("Unsupported SocketAddress");
        }
        InetAddress inet = isa.getAddress();
        int port = isa.getPort();
        ByteBuffer b;

        if (inet != null) {
            byte[] raw = inet.getAddress();
            if (raw.length == 4) {
                b = ByteBuffer.allocate(1 + 1 + 4 + 2 + 2 + payload.length);
                b.put(ft).put((byte) 0x01).put(raw).putShort((short) port);
            } else if (raw.length == 16) {
                b = ByteBuffer.allocate(1 + 1 + 16 + 2 + 2 + payload.length);
                b.put(ft).put((byte) 0x04).put(raw).putShort((short) port);
            } else {
                throw new IOException("Unknown IP length");
            }
        } else {
            byte[] name = isa.getHostString().getBytes(StandardCharsets.UTF_8);
            if (name.length > 255) name = Arrays.copyOf(name, 255);
            b = ByteBuffer.allocate(1 + 1 + 1 + name.length + 2 + 2 + payload.length);
            b.put(ft).put((byte) 0x03).put((byte) name.length).put(name).putShort((short) port);
        }

        b.putShort((short) payload.length).put(payload);
        return b.array();
    }

    // ============================ 加解密帧/工具（会话版） ============================

    /** 写一帧：[4B len][12B nonce + ciphertext|tag]，一次聚合写 */
    static void writeCipherFrame(WritableByteChannel ch, byte[] plain, SessionCipher sess) throws IOException {
        try {
            byte[] packet = sess.encrypt(plain); // [nonce|ct]
            ByteBuffer header = ByteBuffer.allocate(4).putInt(packet.length);
            header.flip();
            ByteBuffer body = ByteBuffer.wrap(packet);
            ByteBuffer[] arr = { header, body };
            long need = header.remaining() + body.remaining();
            long written = 0;
            while (written < need) {
                long n = ((GatheringByteChannel) ch).write(arr);
                if (n <= 0) continue;
                written += n;
            }
        } catch (Exception e) {
            throw new IOException("encrypt/write failed", e);
        }
    }

    /** 读并解密一帧：[4B len][nonce|ct] -> plain */
    static byte[] readCipherFrame(SocketChannel ch, SessionCipher sess) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(4);
        if (!readFully(buf, ch)) throw new IOException("EOF on header");
        buf.flip();
        int cipherLen = buf.getInt();
        if (cipherLen <= 0 || cipherLen > 64 * 1024 + 4096) {
            throw new IOException("Invalid cipher length: " + cipherLen);
        }
        buf = ByteBuffer.allocate(cipherLen);
        if (!readFully(buf, ch)) throw new IOException("EOF on body");
        buf.flip();
        byte[] packet = new byte[cipherLen];
        buf.get(packet);
        try {
            return sess.decrypt(packet);
        } catch (Exception e) {
            throw new IOException("decrypt failed", e);
        }
    }

    // === 读/写直到缓冲用尽；readFully返回false表示遇到EOF ===
    static boolean readFully(ByteBuffer buf, ReadableByteChannel ch) throws IOException {
        while (buf.hasRemaining()) {
            int n = ch.read(buf);
            if (n < 0) return false; // EOF
        }
        return true;
    }

    static void writeFully(WritableByteChannel ch, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            ch.write(buf);
        }
    }

    /** 半关闭输出（允许另一方向继续），忽略异常 */
    static void safeShutdownOutput(SocketChannel ch) {
        try {
            if (ch != null && ch.isOpen()) ch.socket().shutdownOutput();
        } catch (Exception ignore) {}
    }

    /** 安静关闭通道 */
    static void closeQuietly(java.nio.channels.Channel ch) {
        try {
            if (ch != null) ch.close();
        } catch (IOException ignore) {}
    }
}
