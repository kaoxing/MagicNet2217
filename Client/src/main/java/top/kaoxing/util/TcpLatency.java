package top.kaoxing.util;

import java.net.InetSocketAddress;
import java.net.Socket;

public class TcpLatency {

    /**
     * 测量 host:port 的 TCP 延迟，默认尝试 5 次取平均
     */
    public static double measure(String host, int port) {
        return measure(host, port, 5, 3000);
    }

    /**
     * @param host 目标主机
     * @param port 目标端口
     * @param attempts 测量次数
     * @param timeoutMs 单次连接超时 (毫秒)
     * @return 平均延迟 (毫秒)，如果全部失败返回 -1
     */
    public static int measure(String host, int port, int attempts, int timeoutMs) {
        int total = 0;
        int success = 0;

        for (int i = 0; i < attempts; i++) {
            long rtt = oneConnect(host, port, timeoutMs);
            if (rtt >= 0) {
                total += rtt;
                success++;
            }
        }
        return success > 0 ? (total / success) : Integer.MAX_VALUE;
    }

    /** 单次连接建立延迟 (毫秒)，失败返回 -1 */
    private static int oneConnect(String host, int port, int timeoutMs) {
        long start = System.nanoTime();
        try (Socket s = new Socket()) {
            s.setTcpNoDelay(true);
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            long end = System.nanoTime();
            return (int)(end - start) / 1_000_000;
        } catch (Exception e) {
            return -1;
        }
    }

    // 示例：直接运行
    public static void main(String[] args) {
        String host = "fastping1.vpn.kaoxing.top";
        int port = 8001;
        int avg = measure(host, port, 10, 3000);
        if (avg >= 0) {
            System.out.println("Average latency to " + host + ":" + port + " = " + avg + " ms");
        } else {
            System.out.println("All attempts failed.");
        }
    }
}

