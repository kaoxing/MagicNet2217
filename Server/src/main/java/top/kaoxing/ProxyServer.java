package top.kaoxing;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;

public class ProxyServer {

    public static void run() {
        // 启动 TCP 监听
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
//            System.out.println("Accepted TCP connection from " + clientChannel.getRemoteAddress());
            Thread.startVirtualThread(() -> handleTCPClient(clientChannel));
        }
    }

    /**
     * 首帧判别：
     * - 若能按 [ATYP][ADDR][PORT] 精确解析：走 TCP CONNECT。
     * - 否则：按 UDP-over-TCP 处理（首帧即内层UDP帧，FT=0x01）。
     */
    static void handleTCPClient(SocketChannel clientChannel) {
        try {
            // 读第一帧（外层 [4B len][cipher] -> 解密成 first[]）
            byte[] first = readCipherFrame(clientChannel);

            // 尝试当作 CONNECT 目标头
            InetSocketAddress targetAddr = tryParseTargetHeader(first);
            if (targetAddr != null) {
                // ===== CONNECT 模式 =====
                SocketChannel targetChannel = connectTcpTarget(targetAddr);
                Thread t1 = Thread.startVirtualThread(() -> pumpClientToTarget(clientChannel, targetChannel));
                Thread t2 = Thread.startVirtualThread(() -> pumpTargetToClient(targetChannel, clientChannel));
                t1.join();
                t2.join();
                closeQuietly(targetChannel);
                return;
            }

            // ===== UDP-over-TCP 模式 =====
            System.out.println("UDP-over-TCP mode for " + clientChannel.getRemoteAddress());
            DatagramChannel udp = DatagramChannel.open();
            udp.bind(new InetSocketAddress(0)); // 为该 TCP 连接单独开 UDP 口
            udp.configureBlocking(true);

            // 先处理已读到的第一帧（它是内层 UDP 帧）
            pumpTcpToUdpOnce(udp, first);

            Thread t1 = Thread.startVirtualThread(() -> pumpTcpToUdp(clientChannel, udp));
            Thread t2 = Thread.startVirtualThread(() -> pumpUdpToTcp(udp, clientChannel));
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
            target.socket().setTcpNoDelay(true);
            target.socket().setKeepAlive(true);
            target.connect(remote);
            if (!target.isConnected()) throw new IOException("Connect failed to " + remote);
//            System.out.println("Connected to target " + remote);
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
                    return null;
            }
        } catch (Exception ignore) {
            return null;
        }
    }

    // C -> SS -> Target
    static void pumpClientToTarget(SocketChannel client, SocketChannel target) {
        try {
            while (true) {
                byte[] plain = readCipherFrame(client);
                if (plain == null || plain.length == 0) break;
                writeFully(target, ByteBuffer.wrap(plain));
            }
        } catch (IOException ignore) {
        } finally {
            safeShutdownOutput(target);
        }
    }

    // Target -> SS -> C
    static void pumpTargetToClient(SocketChannel target, SocketChannel client) {
        final int CHUNK = 16 * 1024;
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
                writeCipherFrame(client, plain);
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
    static void pumpTcpToUdp(SocketChannel client, DatagramChannel udp) {
        try {
            while (true) {
                byte[] inner = readCipherFrame(client);
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
    static void pumpUdpToTcp(DatagramChannel udp, SocketChannel client) {
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
                writeCipherFrame(client, inner);
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
        java.net.InetAddress inet = isa.getAddress();
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
            // 理论上回包有IP；兜底域名
            byte[] name = isa.getHostString().getBytes(StandardCharsets.UTF_8);
            if (name.length > 255) name = java.util.Arrays.copyOf(name, 255);
            b = ByteBuffer.allocate(1 + 1 + 1 + name.length + 2 + 2 + payload.length);
            b.put(ft).put((byte) 0x03).put((byte) name.length).put(name).putShort((short) port);
        }

        b.putShort((short) payload.length).put(payload);
        return b.array();
    }

    // ============================ 加解密帧/工具 ============================

    /** 写一帧：[4B cipher_len][cipher] */
    static void writeCipherFrame(WritableByteChannel ch, byte[] plain) throws IOException {
        byte[] cipher = (Config.CRYPTION_ENABLED ? Cryptor.encrypt(plain, Config.PASSWORD) : plain);
        if (cipher == null) cipher = new byte[0];

        ByteBuffer header = ByteBuffer.allocate(4);
        header.putInt(cipher.length);
        header.flip();
        writeFully(ch, header);

        if (cipher.length > 0) {
            writeFully(ch, ByteBuffer.wrap(cipher));
        }
    }

    /** 读并解密一帧：[4B cipher_len][cipher] -> plain */
    static byte[] readCipherFrame(SocketChannel ch) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(4);
        if (!readFully(buf, ch)) throw new IOException("EOF on header");
        buf.flip();
        int cipherLen = buf.getInt();
        if (cipherLen <= 0 || cipherLen > 32 * 1024 + 2048) {
            throw new IOException("Invalid cipher length: " + cipherLen);
        }
        buf = ByteBuffer.allocate(cipherLen);
        if (!readFully(buf, ch)) throw new IOException("EOF on body");
        buf.flip();
        byte[] cipher = new byte[cipherLen];
        buf.get(cipher);

        return Config.CRYPTION_ENABLED ? Cryptor.decrypt(cipher, Config.PASSWORD) : cipher;
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
