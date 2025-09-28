package top.kaoxing;

import java.io.EOFException;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;

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
    // shadowocks 代理客户端
    // 对本地表现为一个 SOCKS5 代理服务器
    // 支持CONNECT和UDP ASSOCIATE

    public static void run() throws IOException {
        // 先尝试连接上游服务器，不停重试

        AppLogger.info("Connecting to server " + Config.SERVER_HOST + ":" + Config.SERVER_PORT + " ...");
        while (true) {
            try (SocketChannel test = SocketChannel.open()) {
                test.configureBlocking(true);
                test.connect(new InetSocketAddress(Config.SERVER_HOST, Config.SERVER_PORT));
                AppLogger.info("Connected to server successfully.");
                break;
            } catch (IOException e) {
                AppLogger.warning("Failed to connect to server, retrying in 3 seconds...");
                try { Thread.sleep(3000); } catch (InterruptedException ignored) {}
            }
        }

        try (ServerSocketChannel ssc = ServerSocketChannel.open()) {
            ssc.bind(new InetSocketAddress(Config.LOCAL_PORT));
            AppLogger.info("Proxy Client listening on port " + Config.LOCAL_PORT);
            while (true) {
                SocketChannel sc = ssc.accept();
                Thread.startVirtualThread(() -> handle(sc));
            }
        }
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
        // 1) 先连上游，再回成功
        SocketChannel ssTcp = SocketChannel.open();
        ssTcp.configureBlocking(true);
        ssTcp.connect(new InetSocketAddress(Config.SERVER_HOST, Config.SERVER_PORT)); // SS TCP端口

        // 回 SOCKS5 CONNECT 成功
        ByteBuffer ok = ByteBuffer.allocate(10);
        ok.put((byte) 0x05).put((byte) 0x00).put((byte) 0x00).put((byte) 0x01)
                .put(new byte[]{0, 0, 0, 0}).putShort((short) 0);
        ok.flip();
        sc.write(ok);

        // 2) 首帧发送 SS 目标头（明文）——> 加密后前置4字节密文长度
        ByteBuffer ssHeader = buildSsTcpTargetHeader(shakeHandResult);
        byte[] hdrPlain = new byte[ssHeader.remaining()];
        ssHeader.get(hdrPlain);
        writeCipherFrame(ssTcp, hdrPlain);

//        AppLogger.info("CONNECT " + shakeHandResult.host + ":" + shakeHandResult.port);

        // 3) 双向转发（显式加/解密 + 4字节密文长度前缀）
        Thread tUp = Thread.startVirtualThread(() -> pipeClientToServer(sc, ssTcp));
        Thread tDn = Thread.startVirtualThread(() -> pipeServerToClient(ssTcp, sc));
        try { tUp.join(); tDn.join(); } catch (InterruptedException ignored) {}
        try { ssTcp.close(); } catch (Exception ignored) {}
        try { sc.close(); } catch (Exception ignored) {}
    }

    // === C -> SS：读明文 → 切片 ≤16KB → encrypt → 写 [4B cipher_len][cipher] ===
    static final int CHUNK_MAX = 16 * 1024;

    static void pipeClientToServer(SocketChannel sc, SocketChannel ssTcp) {
        ByteBuffer in = ByteBuffer.allocateDirect(32 * 1024);
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
                    writeCipherFrame(ssTcp, plain);
                }
            }
        } catch (IOException ignored) {
        } finally {
            try { ssTcp.close(); } catch (Exception ignored) {}
            try { sc.close(); } catch (Exception ignored) {}
        }
    }

    // === SS -> C：读 4B 长度 → 读密文 → decrypt → 写回 ===
    static void pipeServerToClient(SocketChannel ssTcp, SocketChannel sc) {
        try {
            while (true) {
                byte[] plain = readCipherFrameTCP(ssTcp);
                if (plain == null) break;
                writeFully(sc, ByteBuffer.wrap(plain));
            }
        } catch (IOException ignored) {
        } finally {
            try { sc.close(); } catch (Exception ignored) {}
            try { ssTcp.close(); } catch (Exception ignored) {}
        }
    }

    // === 写一帧：[4B cipher_len][cipher] ===
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
            // 对纯 IPv6 字面量，JDK 会直接解析为地址字节，不会发起 DNS
            byte[] addr = java.net.InetAddress.getByName(ip).getAddress();
            if (addr.length != 16) throw new IllegalArgumentException("Not IPv6 literal: " + ip);
            return addr;
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad IPv6 literal: " + ip, e);
        }
    }

    // === UDP ASSOCIATE -> UDP-over-TCP 隧道 ===
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
        SocketChannel ssTcp = SocketChannel.open();
        ssTcp.configureBlocking(true);
        ssTcp.connect(new InetSocketAddress(Config.SERVER_HOST, Config.SERVER_PORT));

        ClientAddrHolder holder = new ClientAddrHolder();

//        AppLogger.info("UDP ASSOCIATE, local UDP port " + udpPort);

        // 转发：UDP<->TCP
        Thread tA = Thread.startVirtualThread(() -> pumpClientToServer(udpChannel, ssTcp, sc, holder));
        Thread tB = Thread.startVirtualThread(() -> pumpServerToClient(udpChannel, ssTcp, sc, holder));

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

    // === SOCKS5 握手 ===
    static void readFully(SocketChannel sc, ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            if (sc.read(buf) < 0) throw new EOFException("stream closed");
        }
    }

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

            // 2. 服务器选择认证方法
            buf = ByteBuffer.allocate(2);
            buf.put((byte) 0x05);
            buf.put((byte) 0x00);
            buf.flip();
            sc.write(buf);

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
                                   ClientAddrHolder holder) {
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

                // 外层加密帧 [4B len][cipher] 写 TCP
                writeCipherFrame(serverTCPChannel, inner);
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
                                   ClientAddrHolder holder) {
        ByteBuffer out = ByteBuffer.allocate(65536);

        try {
            while (true) {
                // 读一帧 TCP：[4B len][cipher] -> 解密得到 inner
                byte[] inner = readCipherFrameTCP(serverTCPChannel);
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
    static byte[] readCipherFrameTCP(SocketChannel ch) throws IOException {
        ByteBuffer hdr = ByteBuffer.allocate(4);
        if (!readFully(hdr, ch)) return null; // EOF
        hdr.flip();
        int clen = hdr.getInt();
        if (clen < 0 || clen > 64 * 1024 + 2048) throw new IOException("Bad frame len: " + clen);
        ByteBuffer cbuf = ByteBuffer.allocate(clen);
        if (!readFully(cbuf, ch)) throw new IOException("EOF on TCP body");
        cbuf.flip();
        byte[] cipher = new byte[cbuf.remaining()];
        cbuf.get(cipher);
        return Config.CRYPTION_ENABLED ? Cryptor.decrypt(cipher, Config.PASSWORD) : cipher;
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
