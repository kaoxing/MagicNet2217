package top.kaoxing;


import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        AppLogger.info("Starting client...");
        ProxyClient.run();
    }
}