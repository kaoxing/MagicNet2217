package top.kaoxing.util;

import javax.naming.directory.*;
import javax.naming.*;
import java.util.*;

public class HostListFetcher {
    public static List<String> getHosts(String domain) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        DirContext ctx = new InitialDirContext(env);
        Attributes attrs = ctx.getAttributes(domain, new String[]{"TXT"});
        Attribute attr = attrs.get("TXT");

        List<String> hosts = new ArrayList<>();
        if (attr != null) {
            for (int i = 0; i < attr.size(); i++) {
                String value = attr.get(i).toString().replace("\"", "");
                // 按分号切分
                for (String part : value.split(";")) {
                    String h = part.trim();
                    if (!h.isEmpty()) {
                        hosts.add(h);
                    }
                }
            }
        }
        return hosts;
    }


    public static void main(String[] args) throws Exception {
        List<String> hosts = getHosts("list.vpn.kaoxing.top");
        System.out.println("Available hosts: " + hosts);
    }
}
