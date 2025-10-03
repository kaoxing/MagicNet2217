package top.kaoxing;

import org.yaml.snakeyaml.Yaml;
import java.io.InputStream;
import java.util.List;

class ConfigData {
    public int listen_port;
    public String query_host;
    public int server_port;
    public boolean enable_authentication;
    public String username;
    public String password;
    public boolean use_encryption;
    public String encryption_key;
    public boolean desktop;
}

public class Config {
    public static List<String> server_hosts;
    public static String QUERY_HOST;
    public static String SERVER_HOST;
    public static final int SERVER_PORT;
    public static final int LOCAL_PORT;
    public static final String PASSWORD;
    public static final boolean CRYPTION_ENABLED;
    public static final boolean AUTHENTICATION_ENABLED;
    public static final String USERNAME;
    public static final String AUTH_PASSWORD;
    public static final boolean DESKTOP;
    static{
        Yaml yaml = new Yaml();
        InputStream inputStream = Config.class.getClassLoader().getResourceAsStream("config.yml");
        ConfigData configData = yaml.loadAs(inputStream, ConfigData.class);
        QUERY_HOST = configData.query_host;
        SERVER_PORT = configData.server_port;
        LOCAL_PORT = configData.listen_port;
        PASSWORD = configData.encryption_key;
        CRYPTION_ENABLED = configData.use_encryption;
        AUTHENTICATION_ENABLED = configData.enable_authentication;
        USERNAME = configData.username;
        AUTH_PASSWORD = configData.password;
        DESKTOP = configData.desktop;
    }
    public static void selectHost(int index) {
        if (index < 0 || index >= server_hosts.size()) {
            throw new IndexOutOfBoundsException("Index out of bounds: " + index);
        }
        SERVER_HOST = server_hosts.get(index);
    }
    public static void setHost(String host){
        SERVER_HOST = host;
    }
}
