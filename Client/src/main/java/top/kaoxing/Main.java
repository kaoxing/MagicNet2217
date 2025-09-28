package top.kaoxing;


import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        // 按照用户控制台输入选择服务器
        //1. 打印服务器列表
        System.out.println("Available server hosts:");
        System.out.println("0: Enter manually");
        for (int i = 0; i < Config.server_hosts.size(); i++) {
            System.out.println((i+1) + ": " + Config.server_hosts.get(i).host_name);
        }
        //2. 读取用户输入
        System.out.print("Select a server host by index: ");
        byte[] inputBuffer = new byte[255];
        int bytesRead = System.in.read(inputBuffer);
        String input = new String(inputBuffer, 0, bytesRead).trim();
        int selectedIndex;
        try {
            selectedIndex = Integer.parseInt(input);
            if(selectedIndex == 0){
                // 用户输入0，手动输入服务器地址
                System.out.print("Enter server host address: ");
                bytesRead = System.in.read(inputBuffer);
                String hostInput = new String(inputBuffer, 0, bytesRead).trim();
                Config.setHost(hostInput);
                System.out.println("Selected host: " + Config.SERVER_HOST);
            }else if(selectedIndex > 0 && selectedIndex <= Config.server_hosts.size()){
                // 用户输入有效索引，选择对应服务器
                selectedIndex = selectedIndex - 1; // 转换为0-based索引
                System.out.println("Selected host: " + Config.server_hosts.get(selectedIndex).host_name);
                Config.selectHost(selectedIndex);
            }else{
                throw new IndexOutOfBoundsException("Index out of bounds: " + selectedIndex);
            }
        } catch (NumberFormatException | IndexOutOfBoundsException e) {
            System.out.println("Invalid input. Exiting.");
            return;
        }
        AppLogger.info("Starting client...");
        ProxyClient.run();
    }
}