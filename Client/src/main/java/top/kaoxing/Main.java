package top.kaoxing;


import top.kaoxing.util.*;

import java.io.IOException;
import java.util.Comparator;

public class Main {
    public static void main(String[] args) throws IOException {
        try {
            System.out.println("Searching for available server hosts...");
            // 查询可用服务器列表
            Config.server_hosts = HostListFetcher.getHosts(Config.QUERY_HOST);
            Config.server_hosts.sort(Comparator.comparingInt(h -> TcpLatency.measure(h, Config.SERVER_PORT, 5, 1000)));
            if (Config.DESKTOP) {
                // 按照用户控制台输入选择服务器
                //1. 打印服务器列表
                System.out.println("Available server hosts:");
                System.out.println("0: Enter manually");
                for (int i = 0; i < Config.server_hosts.size(); i++) {
                    int latency = TcpLatency.measure(Config.server_hosts.get(i), Config.SERVER_PORT, 3, 1000);
                    if (latency != Integer.MAX_VALUE) {
                        System.out.println((i + 1) + ": " + Config.server_hosts.get(i)+ " (" + latency + " ms)");
                    }else{
                        System.out.println((i + 1) + ": " + Config.server_hosts.get(i)+ " (unreachable)");
                    }

                }
                //2. 读取用户输入
                System.out.print("Select a server host by index: ");
                byte[] inputBuffer = new byte[255];
                int bytesRead = System.in.read(inputBuffer);
                String input = new String(inputBuffer, 0, bytesRead).trim();
                int selectedIndex;
                try {
                    selectedIndex = Integer.parseInt(input);
                    if (selectedIndex == 0) {
                        // 用户输入0，手动输入服务器地址
                        System.out.print("Enter server host address: ");
                        bytesRead = System.in.read(inputBuffer);
                        String hostInput = new String(inputBuffer, 0, bytesRead).trim();
                        Config.setHost(hostInput);
                        System.out.println("Selected host: " + Config.SERVER_HOST);
                    } else if (selectedIndex > 0 && selectedIndex <= Config.server_hosts.size()) {
                        // 用户输入有效索引，选择对应服务器
                        selectedIndex = selectedIndex - 1; // 转换为0-based索引
                        System.out.println("Selected host: " + Config.server_hosts.get(selectedIndex));
                        Config.selectHost(selectedIndex);
                    } else {
                        throw new IndexOutOfBoundsException("Index out of bounds: " + selectedIndex);
                    }
                } catch (NumberFormatException | IndexOutOfBoundsException e) {
                    System.out.println("Invalid input. Exiting.");
                    return;
                }
            } else {
                // 直接选择
                Config.selectHost(0);
            }
            ProxyClient.run();
        }catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error: " + e.getMessage());
        }
    }
}