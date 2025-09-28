package top.kaoxing;

import java.io.IOException;
import java.util.logging.*;

public class AppLogger {
    private static final Logger logger = Logger.getLogger("GlobalLogger");

    static {
        try {
            logger.setUseParentHandlers(false); // 避免重复日志

            // 控制台输出
            ConsoleHandler consoleHandler = new ConsoleHandler();
            consoleHandler.setLevel(Level.ALL);

            // 文件输出
            FileHandler fileHandler = new FileHandler("app.log", true); // 追加模式
            fileHandler.setLevel(Level.ALL);
            fileHandler.setFormatter(new SimpleFormatter());

            // 绑定 handler
            logger.addHandler(consoleHandler);
            logger.addHandler(fileHandler);

            logger.setLevel(Level.ALL);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // === 封装方法 ===
    public static void info(String msg) {
        logger.info(msg);
    }

    public static void warning(String msg) {
        logger.warning(msg);
    }

    public static void error(String msg) {
        logger.severe(msg);
    }

    // 如果想支持异常日志
    public static void error(String msg, Throwable t) {
        logger.log(Level.SEVERE, msg, t);
    }
}
