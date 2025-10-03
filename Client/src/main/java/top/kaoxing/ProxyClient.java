package top.kaoxing;

import top.kaoxing.util.TcpLatency;

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

enum Command {
    FAILED,
    CONNECT,
    UDP_ASSOCIATE
}

class ShakeHandResult {
    static final ShakeHandResult FAILED = new ShakeHandResult(Command.FAILED, (byte)0, null, -1);
    final Command command;
    final byte atyp;       // 原始 ATYP: 0x01/0x03/0x04
    final String host;     // 若 ATYP=0x03 为域名；ATYP=0x01/0x04 为字面 IP
    final int port;

    ShakeHandResult(Command command, byte atyp, String host, int port) {
        this.command = command;
        this.atyp = atyp;
        this.host = host;
        this.port = port;
    }
}

class ClientAddrHolder {
    volatile SocketAddress addr; // 第一次收到本地UDP时写入
}

public class ProxyClient {
    // ============================================================
    // 会话加密器（SS-libev 风格）：TCP 连接首包发 salt(16)，HKDF → subkey
    // 每帧: [4B len][12B nonce][cipher|tag]
    // ============================================================
    static final class SessionCipher {
        private static final SecureRandom RNG = new SecureRandom();

        // 你自定义的信息串
        private static final byte[] HKDF_INFO = "kaoxing123".getBytes(StandardCharsets.US_ASCII);

        // 自定义握手前缀，避免与 libev 长得一样
        private static final byte   PROTO_MAGIC = (byte)0xB7;
        private static final byte   PROTO_VER   = 0x02;

        // 改成 24 字节 salt
        private static final int SALT_LEN = 24;

        private final SecretKeySpec subKey; // 32B -> AES key
        private final Cipher enc;
        private final Cipher dec;
        private long sendCounter = 0;     // 96-bit nonce 的低64位

        private SessionCipher(byte[] masterKey, byte[] salt) throws Exception {
            byte[] sk = hkdf(masterKey, salt, HKDF_INFO, 32);
            this.subKey = new SecretKeySpec(sk, "AES");
            Arrays.fill(sk, (byte) 0);
            this.enc = Cipher.getInstance("AES/GCM/NoPadding");
            this.dec = Cipher.getInstance("AES/GCM/NoPadding");
        }

        // 客户端握手：发送 [MAGIC][VER][salt]
        static SessionCipher clientHandshake(SocketChannel ch, String password) throws IOException {
            try {
                byte[] master = masterKeyFromPassword(password);
                byte[] salt = new byte[SALT_LEN];
                RNG.nextBytes(salt);

                ByteBuffer hello = ByteBuffer.allocate(2 + SALT_LEN);
                hello.put(PROTO_MAGIC).put(PROTO_VER).put(salt).flip();
                writeFully(ch, hello);

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

        // 解密：输入 [12B nonce][cipher|tag]
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
            // 高32位保留 0，低64位为计数（两端一致即可）
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

        // ---------- HKDF (HMAC-SHA1 版，与 libev 传统一致；也可换成 HMAC-SHA256) ----------
        private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
            byte[] prk = hkdfExtract(salt, ikm);
            return hkdfExpand(prk, info, len);
        }
        private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return mac.doFinal(ikm);
        }
        private static byte[] hkdfExpand(byte[] prk, byte[] info, int len) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
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

    // ============================================================

    public static void run() throws IOException {
        // 先尝试连接上游服务器，不停重试
        AppLogger.info("Connecting to server " + Config.SERVER_HOST + ":" + Config.SERVER_PORT + " ...");
        while (true) {
            try (SocketChannel test = SocketChannel.open()) {
                test.configureBlocking(true);
                test.connect(new InetSocketAddress(Config.SERVER_HOST, Config.SERVER_PORT));
                AppLogger.info("Connected to server successfully.");
                break;
            } catch (Exception e) {
                AppLogger.warning("Failed to connect to server, retrying in 3 seconds...");
                try { Thread.sleep(3000); } catch (InterruptedException ignored) {}
            }
        }

        // 开一个线程定时测试服务器延迟，打印到日志
        Thread.startVirtualThread(() -> {
            while (true) {
                try {
                    int latency = TcpLatency.measure(Config.SERVER_HOST, Config.SERVER_PORT, 3, 1000);
                    if (latency != Integer.MAX_VALUE) {
                        AppLogger.info("Current latency to server " + Config.SERVER_HOST + ": " + latency + " ms");
                    } else {
                        AppLogger.warning("Server " + Config.SERVER_HOST + ":" + Config.SERVER_PORT + " is unreachable.");
                        break;
                    }
                    Thread.sleep(20000); // 每20秒测一次
                } catch (InterruptedException e) {
                    break; // 线程被中断，退出
                }
            }
        });

        try (ServerSocketChannel ssc = ServerSocketChannel.open()) {
            ssc.bind(new InetSocketAddress(Config.LOCAL_PORT));
            AppLogger.info("Proxy Client listening on port " + Config.LOCAL_PORT);
            while (true) {
                SocketChannel sc = ssc.accept();
                sc.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
                sc.setOption(StandardSocketOptions.TCP_NODELAY, true);
                sc.setOption(StandardSocketOptions.SO_SNDBUF, 4 * 1024 * 1024);
                sc.setOption(StandardSocketOptions.SO_RCVBUF, 4 * 1024 * 1024);
                Thread.startVirtualThread(() -> handle(sc));
            }
        } catch (Exception e) {
            AppLogger.warning("Local server error, exiting: " + e.getMessage());
        }
    }

    static SocketChannel dialUpstream() throws IOException {
        SocketChannel ch = SocketChannel.open();
        ch.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
        ch.setOption(StandardSocketOptions.TCP_NODELAY, true); // 小包多时有利；用户态已做聚合
        ch.setOption(StandardSocketOptions.SO_SNDBUF, 4 * 1024 * 1024);
        ch.setOption(StandardSocketOptions.SO_RCVBUF, 4 * 1024 * 1024);
        ch.configureBlocking(true);
        ch.connect(new InetSocketAddress(Config.SERVER_HOST, Config.SERVER_PORT));
        return ch;
    }

    static void handle(SocketChannel sc) {
        try (sc) {
            // 1. 与本地客户端完成 SOCKS5 握手
            ShakeHandResult shakeHandResult = socks5ShakeHand(sc);
            if (shakeHandResult == ShakeHandResult.FAILED) {
                AppLogger.warning("SOCKS5 handshake failed");
                return;
            }

            // 判断是 CONNECT 还是 UDP ASSOCIATE
            if (shakeHandResult.command == Command.CONNECT) {
                handleConnect(sc, shakeHandResult);
            } else {
                handleUdpAssociate(sc);
            }

        } catch (IOException ignored) {}
    }

    // === CONNECT ===
    static void handleConnect(SocketChannel sc, ShakeHandResult shakeHandResult) throws IOException {
        SocketChannel ssTcp = dialUpstream();

        // ===== SS-libev风格：握手首包发送 salt，派生会话子密钥 =====
        SessionCipher sess = SessionCipher.clientHandshake(ssTcp, Config.PASSWORD);

        // 回 SOCKS5 CONNECT 成功
        ByteBuffer ok = ByteBuffer.allocate(10);
        ok.put((byte) 0x05).put((byte) 0x00).put((byte) 0x00).put((byte) 0x01)
                .put(new byte[]{0, 0, 0, 0}).putShort((short) 0);
        ok.flip();
        sc.write(ok);

        // 2) 首帧发送目标头（加密后发送，帧内含 [nonce][ct]）
        ByteBuffer ssHeader = buildSsTcpTargetHeader(shakeHandResult);
        byte[] hdrPlain = new byte[ssHeader.remaining()];
        ssHeader.get(hdrPlain);
        writeCipherFrame(ssTcp, hdrPlain, sess);

        // 3) 双向转发
        Thread tUp = Thread.startVirtualThread(() -> pipeClientToServer(sc, ssTcp, sess));
        Thread tDn = Thread.startVirtualThread(() -> pipeServerToClient(ssTcp, sc, sess));
        try { tUp.join(); tDn.join(); } catch (InterruptedException ignored) {}
        try { ssTcp.close(); } catch (Exception ignored) {}
        try { sc.close(); } catch (Exception ignored) {}
    }

    // === C -> SS：读明文 → 切片 ≤64KB → 会话加密 → 写 [4B frame_len][nonce+ct] ===
    static final int CHUNK_MAX = 64 * 1024;

    static void pipeClientToServer(SocketChannel sc, SocketChannel ssTcp, SessionCipher sess) {
        ByteBuffer in = ByteBuffer.allocateDirect(64 * 1024);
        try {
            while (true) {
                in.clear();
                int n = sc.read(in);
                if (n == -1) break;
                if (n == 0) continue;
                in.flip();
                while (in.hasRemaining()) {
                    int take = Math.min(in.remaining(), CHUNK_MAX);
                    byte[] plain = new byte[take];
                    in.get(plain);
                    writeCipherFrame(ssTcp, plain, sess);
                }
            }
        } catch (IOException ignored) {
        } finally {
            try { ssTcp.close(); } catch (Exception ignored) {}
            try { sc.close(); } catch (Exception ignored) {}
        }
    }

    // === SS -> C：读 [4B len][nonce+ct] → 解密 → 写回 ===
    static void pipeServerToClient(SocketChannel ssTcp, SocketChannel sc, SessionCipher sess) {
        try {
            while (true) {
                byte[] plain = readCipherFrameTCP(ssTcp, sess);
                if (plain == null) break;
                writeFully(sc, ByteBuffer.wrap(plain));
            }
        } catch (IOException ignored) {
        } finally {
            try { sc.close(); } catch (Exception ignored) {}
            try { ssTcp.close(); } catch (Exception ignored) {}
        }
    }

    // === 写一帧：[4B frame_len][12B nonce + ciphertext|tag]，一次聚合写 ===
    static void writeCipherFrame(WritableByteChannel ch, byte[] plain, SessionCipher sess) throws IOException {
        try {
            byte[] packet = sess.encrypt(plain); // [nonce(12)|ct|tag]
            ByteBuffer header = ByteBuffer.allocate(4).putInt(packet.length);
            header.flip();
            ByteBuffer body = ByteBuffer.wrap(packet);
            // gather write
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

    // === 工具：读/写直到缓冲用尽；readFully返回false表示遇到EOF ===
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

    // === 构造 [ATYP][ADDR][PORT] 目标头（严格按握手的 ATYP 原样封装；不做解析） ===
    static ByteBuffer buildSsTcpTargetHeader(ShakeHandResult sh) {
        if (sh.port < 0 || sh.port > 65535) {
            throw new IllegalArgumentException("port out of range: " + sh.port);
        }

        switch (sh.atyp & 0xFF) {
            case 0x03: { // DOMAIN
                byte[] name = sh.host.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                if (name.length == 0 || name.length > 255) {
                    throw new IllegalArgumentException("Domain length invalid: " + name.length);
                }
                ByteBuffer buf = ByteBuffer.allocate(1 + 1 + name.length + 2);
                buf.put((byte)0x03).put((byte)name.length).put(name).putShort((short)(sh.port & 0xFFFF));
                buf.flip();
                return buf;
            }
            case 0x01: { // IPv4 字面量
                byte[] v4 = parseIPv4Literal(sh.host);
                ByteBuffer buf = ByteBuffer.allocate(1 + 4 + 2);
                buf.put((byte)0x01).put(v4).putShort((short)(sh.port & 0xFFFF));
                buf.flip();
                return buf;
            }
            case 0x04: { // IPv6 字面量
                byte[] v6 = parseIPv6Literal(sh.host); // 仅解析字面量，不做 DNS
                ByteBuffer buf = ByteBuffer.allocate(1 + 16 + 2);
                buf.put((byte)0x04).put(v6).putShort((short)(sh.port & 0xFFFF));
                buf.flip();
                return buf;
            }
            default:
                throw new IllegalArgumentException("Unsupported ATYP: " + sh.atyp);
        }
    }

    // —— 工具：只解析“字面量”地址，避免触发本地 DNS —— //
    static byte[] parseIPv4Literal(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) throw new IllegalArgumentException("Bad IPv4 literal: " + ip);
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            int v = Integer.parseInt(p[i]);
            if (v < 0 || v > 255) throw new IllegalArgumentException("Bad IPv4 octet: " + p[i]);
            b[i] = (byte) v;
        }
        return b;
    }

    static byte[] parseIPv6Literal(String ip) {
        try {
            byte[] addr = java.net.InetAddress.getByName(ip).getAddress();
            if (addr.length != 16) throw new IllegalArgumentException("Not IPv6 literal: " + ip);
            return addr;
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad IPv6 literal: " + ip, e);
        }
    }

    // === UDP ASSOCIATE -> UDP-over-TCP 隧道（同一 TCP 会话加密器） ===
    static void handleUdpAssociate(SocketChannel sc) throws IOException {
        // 给本地应用回 SOCKS5 UDP 成功 & 分配一个本地 UDP 端口供其发送
        ByteBuffer buf = ByteBuffer.allocate(10);
        buf.put((byte) 0x05); // VER
        buf.put((byte) 0x00); // REP = succeeded
        buf.put((byte) 0x00); // RSV
        buf.put((byte) 0x01); // ATYP = IPv4
        InetSocketAddress localAddr = (InetSocketAddress) sc.getLocalAddress();
        InetAddress bindIP = localAddr.getAddress();
        byte[] ipBytes = bindIP.getAddress(); // IPv4
        buf.put(ipBytes); // BND.ADDR
        DatagramChannel udpChannel = DatagramChannel.open();
        udpChannel.bind(new InetSocketAddress(0)); // 随机 UDP 端口供本地应用发来
        int udpPort = ((InetSocketAddress) udpChannel.getLocalAddress()).getPort();
        buf.putShort((short) udpPort); // BND.PORT
        buf.flip();
        sc.write(buf);

        // 与服务端建立 TCP 隧道（承载 UDP 内帧）
        SocketChannel ssTcp = dialUpstream();
        SessionCipher sess = SessionCipher.clientHandshake(ssTcp, Config.PASSWORD);

        ClientAddrHolder holder = new ClientAddrHolder();

        Thread tA = Thread.startVirtualThread(() -> pumpClientToServer(udpChannel, ssTcp, sc, holder, sess));
        Thread tB = Thread.startVirtualThread(() -> pumpServerToClient(udpChannel, ssTcp, sc, holder, sess));

        // 维持 TCP 控制信道直到本地关闭
        ByteBuffer sink = ByteBuffer.allocate(1);
        try {
            while (true) {
                int n = sc.read(sink);
                if (n < 0) break;
                sink.clear();
            }
        } finally {
            try { udpChannel.close(); } catch (Exception ignored) {}
            try { ssTcp.close(); } catch (Exception ignored) {}
            try { sc.close(); } catch (Exception ignored) {}
            try { tA.join(); tB.join(); } catch (InterruptedException ignored) {}
        }
    }

    static void readFully(SocketChannel sc, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            if (sc.read(buf) < 0) throw new EOFException("stream closed");
        }
    }

    // === SOCKS5 握手（原样） ===
    static ShakeHandResult socks5ShakeHand(SocketChannel sc) {
        ByteBuffer buf = ByteBuffer.allocate(2);
        try {
            // 1. 客户端问候
            readFully(sc, buf);
            buf.flip();
            if (buf.get() != 0x05) {
                AppLogger.warning("Unsupported SOCKS version: " + buf.get(0));
                return ShakeHandResult.FAILED;
            }
            int nMethods = buf.get();
            if (nMethods <= 0) {
                AppLogger.warning("No authentication methods provided");
                return ShakeHandResult.FAILED;
            }
            buf = ByteBuffer.allocate(nMethods);
            readFully(sc, buf);
            buf.flip();

            if (!Config.AUTHENTICATION_ENABLED){
                boolean noAuth = false;
                for (int i = 0; i < nMethods; i++) {
                    if (buf.get() == 0x00) {
                        noAuth = true;
                        break;
                    }
                }
                if (!noAuth) {
                    AppLogger.error("No supported authentication methods");
                    return ShakeHandResult.FAILED;
                }
            }

            // 2. 服务器选择认证方法
            if(Config.AUTHENTICATION_ENABLED){
                buf = ByteBuffer.allocate(2);
                buf.put((byte) 0x05);
                buf.put((byte) 0x02);
                buf.flip();
                sc.write(buf);

                // 用户名/密码认证子协商
                buf = ByteBuffer.allocate(2);
                readFully(sc, buf);
                buf.flip();
                if (buf.get() != 0x01) {
                    AppLogger.warning("Unsupported auth version: " + buf.get(0));
                    return ShakeHandResult.FAILED;
                }

                int ulen = buf.get() & 0xFF;
                if (ulen <= 0 || ulen > 255) {
                    AppLogger.warning("Invalid username length: " + ulen);
                    return ShakeHandResult.FAILED;
                }
                buf = ByteBuffer.allocate(ulen + 1);
                readFully(sc, buf);
                buf.flip();
                byte[] unameBytes = new byte[ulen];
                buf.get(unameBytes);
                String username = new String(unameBytes, StandardCharsets.US_ASCII);
                int plen = buf.get() & 0xFF;
                if (plen <= 0 || plen > 255) {
                    AppLogger.warning("Invalid password length: " + plen);
                    return ShakeHandResult.FAILED;
                }
                buf = ByteBuffer.allocate(plen);
                readFully(sc, buf);
                buf.flip();
                byte[] passwdBytes = new byte[plen];
                buf.get(passwdBytes);
                String password = new String(passwdBytes, StandardCharsets.US_ASCII);
                if (!username.equals(Config.USERNAME) || !password.equals(Config.AUTH_PASSWORD)) {
                    AppLogger.warning("Authentication failed for user: " + username);
                    buf = ByteBuffer.allocate(2);
                    buf.put((byte) 0x01);
                    buf.put((byte) 0x01); // 失败
                    buf.flip();
                    sc.write(buf);
                    return ShakeHandResult.FAILED;
                } else {
                    buf = ByteBuffer.allocate(2);
                    buf.put((byte) 0x01);
                    buf.put((byte) 0x00); // 成功
                    buf.flip();
                    sc.write(buf);
                }
            }else{
                buf = ByteBuffer.allocate(2);
                buf.put((byte) 0x05);
                buf.put((byte) 0x00);
                buf.flip();
                sc.write(buf);
            }

            // 3. 客户端请求
            buf = ByteBuffer.allocate(4);
            readFully(sc, buf);
            buf.flip();
            if (buf.get() != 0x05) {
                AppLogger.warning("Unsupported SOCKS version in request: " + buf.get(0));
                return ShakeHandResult.FAILED;
            }
            byte cmd = buf.get();
            if (cmd != 0x01 && cmd != 0x03) {
                AppLogger.warning("Unsupported command: " + cmd);
                return ShakeHandResult.FAILED;
            }
            buf.get(); // RSV
            byte atyp = buf.get();
            if (atyp != 0x01 && atyp != 0x03 && atyp != 0x04) {
                AppLogger.warning("Unsupported address type: " + atyp);
                return ShakeHandResult.FAILED;
            }

            // 4. 读取目标地址和端口
            String destAddr;
            if (atyp == 0x01) {
                buf = ByteBuffer.allocate(4);
                readFully(sc, buf);
                buf.flip();
                destAddr = String.format("%d.%d.%d.%d",
                        buf.get() & 0xFF, buf.get() & 0xFF, buf.get() & 0xFF, buf.get() & 0xFF);
            } else if (atyp == 0x03) {
                buf = ByteBuffer.allocate(1);
                readFully(sc, buf);
                buf.flip();
                int domainLen = buf.get() & 0xFF;
                buf = ByteBuffer.allocate(domainLen);
                readFully(sc, buf);
                buf.flip();
                byte[] domainBytes = new byte[domainLen];
                buf.get(domainBytes);
                destAddr = new String(domainBytes, StandardCharsets.US_ASCII);
            } else {
                buf = ByteBuffer.allocate(16);
                readFully(sc, buf);
                buf.flip();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i++) {
                    sb.append(String.format("%x", (buf.getShort() & 0xFFFF)));
                    if (i < 7) sb.append(":");
                }
                destAddr = sb.toString();
            }
            buf = ByteBuffer.allocate(2);
            readFully(sc, buf);
            buf.flip();
            int destPort = buf.getShort() & 0xFFFF;

            return new ShakeHandResult(
                    (cmd == 0x01 ? Command.CONNECT : Command.UDP_ASSOCIATE),
                    atyp,
                    destAddr,
                    destPort
            );

        } catch (IOException e) {
            AppLogger.error("IO error during SOCKS5 handshake", e);
            return ShakeHandResult.FAILED;
        }
    }

    // ========================= UDP over TCP: C <-> SS =========================

    // C(UDP/SOCKS5) -> SS(TCP)
    static void pumpClientToServer(DatagramChannel udpChannel,
                                   SocketChannel serverTCPChannel,
                                   SocketChannel sc,
                                   ClientAddrHolder holder,
                                   SessionCipher sess) {
        ByteBuffer in = ByteBuffer.allocate(65536);  // UDP max
        ByteBuffer out = ByteBuffer.allocate(65536);

        try {
            while (true) {
                in.clear();
                SocketAddress from = udpChannel.receive(in); // 阻塞
                if (from == null) continue;
                if (holder.addr == null) holder.addr = from; // 记录一次回包目的

                in.flip();
                // SOCKS5 UDP：RSV(2)=0, FRAG(1)=0
                if (in.remaining() < 4) continue;
                byte r0 = in.get(), r1 = in.get(), frag = in.get();
                if (r0 != 0 || r1 != 0 || frag != 0) continue;

                byte atyp = in.get();
                byte[] dst;
                switch (atyp) {
                    case 0x01: // IPv4
                        if (in.remaining() < 4 + 2) continue;
                        dst = new byte[4]; in.get(dst);
                        break;
                    case 0x03: // DOMAIN
                        if (in.remaining() < 1) continue;
                        int len = in.get() & 0xFF;
                        if (in.remaining() < len + 2) continue;
                        dst = new byte[1 + len];
                        dst[0] = (byte) len;       // 域名需要带长度
                        in.get(dst, 1, len);
                        break;
                    case 0x04: // IPv6
                        if (in.remaining() < 16 + 2) continue;
                        dst = new byte[16]; in.get(dst);
                        break;
                    default:
                        continue;
                }

                short portBE = in.getShort(); // 网络序端口
                byte[] payload = new byte[in.remaining()];
                in.get(payload);

                // 构造“内层 UDP 帧”：FT=0x01 + [ATYP][DST][PORT] + [2B LEN] + DATA
                byte[] inner = buildInnerUdpFrame((byte) 0x01, atyp, dst, portBE, payload);

                // 外层加密帧 [4B len][nonce+ct] 写 TCP
                writeCipherFrame(serverTCPChannel, inner, sess);
            }
        } catch (Exception e) {
            try { sc.close(); } catch (Exception ignored) {}
            try { udpChannel.close(); } catch (Exception ignored) {}
            try { serverTCPChannel.close(); } catch (Exception ignored) {}
        }
    }

    // SS(TCP) -> C(UDP/SOCKS5)
    static void pumpServerToClient(DatagramChannel udpChannel,
                                   SocketChannel serverTCPChannel,
                                   SocketChannel sc,
                                   ClientAddrHolder holder,
                                   SessionCipher sess) {
        ByteBuffer out = ByteBuffer.allocate(65536);

        try {
            while (true) {
                // 读一帧 TCP：[4B len][nonce+ct] -> 解密得到 inner
                byte[] inner = readCipherFrameTCP(serverTCPChannel, sess);
                if (inner == null || inner.length == 0) continue;

                ByteBuffer p = ByteBuffer.wrap(inner);
                if (p.remaining() < 1 + 1 + 2) continue; // 至少 FT + ATYP + (后续PORT在地址后出现)

                byte ft = p.get();
                if (ft != 0x02) {
                    // 只处理 S->C 的回包类型
                    continue;
                }

                // 解析 [ATYP][ADDR][PORT]
                int mark = p.position();
                InetSocketAddress fromTarget = readAtypAddrPortForInner(p);

                // 读 [2B LEN] + DATA
                if (p.remaining() < 2) continue;
                int dlen = Short.toUnsignedInt(p.getShort());
                if (p.remaining() < dlen) continue;
                byte[] data = new byte[dlen];
                p.get(data);

                // 组 SOCKS5 UDP 响应：RSV=0, FRAG=0, ATYP, DST, PORT, DATA
                out.clear();
                out.put((byte) 0).put((byte) 0).put((byte) 0); // RSV(2), FRAG(1)

                // 重放地址字段
                p.position(mark);
                byte atyp = p.get();
                out.put(atyp);
                switch (atyp & 0xFF) {
                    case 0x01: { byte[] ip = new byte[4]; p.get(ip); out.put(ip); break; }
                    case 0x03: { int n = p.get() & 0xFF; out.put((byte) n);
                        byte[] nm = new byte[n]; p.get(nm); out.put(nm); break; }
                    case 0x04: { byte[] ip6 = new byte[16]; p.get(ip6); out.put(ip6); break; }
                    default: continue;
                }
                out.putShort((short) fromTarget.getPort()); // PORT (network order)
                out.put(data);
                out.flip();

                SocketAddress client = holder.addr;
                if (client != null) {
                    udpChannel.send(out, client);
                }
            }
        } catch (Exception e) {
            try { sc.close(); } catch (Exception ignored) {}
            try { udpChannel.close(); } catch (Exception ignored) {}
            try { serverTCPChannel.close(); } catch (Exception ignored) {}
        }
    }

    // === 内层 UDP 帧工具：FT + [ATYP][ADDR][PORT] + [2B LEN] + DATA ===
    static byte[] buildInnerUdpFrame(byte ft, byte atyp, byte[] dstPart, short portBE, byte[] payload) {
        int addrLen = switch (atyp & 0xFF) {
            case 0x01 -> 4;
            case 0x03 -> 1 + (dstPart[0] & 0xFF); // len + name
            case 0x04 -> 16;
            default -> 0;
        };
        ByteBuffer b = ByteBuffer.allocate(1 + 1 + addrLen + 2 + 2 + payload.length);
        b.put(ft).put(atyp);
        if ((atyp & 0xFF) == 0x03) {
            b.put(dstPart, 0, 1 + (dstPart[0] & 0xFF));
        } else {
            b.put(dstPart, 0, addrLen);
        }
        b.putShort(portBE);
        b.putShort((short) payload.length);
        b.put(payload);
        return b.array();
    }

    // 从 TCP 读取一帧并解密为 inner 明文
    static byte[] readCipherFrameTCP(SocketChannel ch, SessionCipher sess) throws IOException {
        ByteBuffer hdr = ByteBuffer.allocate(4);
        if (!readFully(hdr, ch)) return null; // EOF
        hdr.flip();
        int clen = hdr.getInt();
        if (clen < 0 || clen > 64 * 1024 + 4096) throw new IOException("Bad frame len: " + clen);
        ByteBuffer cbuf = ByteBuffer.allocate(clen);
        if (!readFully(cbuf, ch)) throw new IOException("EOF on TCP body");
        cbuf.flip();
        byte[] packet = new byte[cbuf.remaining()];
        cbuf.get(packet);
        try {
            return sess.decrypt(packet); // packet = [nonce|ct]
        } catch (Exception e) {
            throw new IOException("decrypt failed", e);
        }
    }

    // 解析 inner 帧里的 [ATYP][ADDR][PORT]
    static InetSocketAddress readAtypAddrPortForInner(ByteBuffer bb) throws IOException {
        if (bb.remaining() < 1 + 2) throw new IOException("short header");
        int atyp = bb.get() & 0xFF;
        switch (atyp) {
            case 0x01: { // IPv4
                if (bb.remaining() < 4 + 2) throw new IOException("short ipv4");
                byte[] ip = new byte[4]; bb.get(ip);
                int port = Short.toUnsignedInt(bb.getShort());
                return new InetSocketAddress(java.net.InetAddress.getByAddress(ip), port);
            }
            case 0x03: { // DOMAIN
                int len = bb.get() & 0xFF;
                if (bb.remaining() < len + 2) throw new IOException("short domain");
                byte[] name = new byte[len]; bb.get(name);
                int port = Short.toUnsignedInt(bb.getShort());
                String host = new String(name, java.nio.charset.StandardCharsets.UTF_8);
                return new InetSocketAddress(host, port);
            }
            case 0x04: { // IPv6
                if (bb.remaining() < 16 + 2) throw new IOException("short ipv6");
                byte[] ip = new byte[16]; bb.get(ip);
                int port = Short.toUnsignedInt(bb.getShort());
                return new InetSocketAddress(java.net.InetAddress.getByAddress(ip), port);
            }
            default:
                throw new IOException("bad ATYP " + atyp);
        }
    }
}
