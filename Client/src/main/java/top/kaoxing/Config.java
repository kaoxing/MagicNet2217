package top.kaoxing;

import org.yaml.snakeyaml.Yaml;
import java.io.InputStream;

class ConfigData {
    public String server_host;
    public int server_port;
    public int listen_port;
    public String encryption_key;
    public boolean use_encryption;
}

public class Config {
    public static final String SERVER_HOST;
    public static final int SERVER_PORT;
    public static final int LOCAL_PORT;
    public static final String PASSWORD;
    public static final boolean CRYPTION_ENABLED;
    static{
        Yaml yaml = new Yaml();
        InputStream inputStream = Config.class.getClassLoader().getResourceAsStream("config.yml");
        ConfigData configData = yaml.loadAs(inputStream, ConfigData.class);
        SERVER_HOST = configData.server_host;
        SERVER_PORT = configData.server_port;
        LOCAL_PORT = configData.listen_port;
        PASSWORD = configData.encryption_key;
        CRYPTION_ENABLED = configData.use_encryption;
    }
}
