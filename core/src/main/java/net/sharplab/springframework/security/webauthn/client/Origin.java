package net.sharplab.springframework.security.webauthn.client;

import java.io.Serializable;
import java.net.URI;

/**
 * Origin
 */
public class Origin implements Serializable {
    private String scheme;
    private String serverName;
    private int port;

    public Origin(String scheme, String serverName, int port) {
        this.scheme = scheme;
        this.serverName = serverName;
        this.port = port;
    }

    public Origin(String originUrl){
        URI uri = URI.create(originUrl);
        this.scheme = uri.getScheme();
        this.serverName = uri.getHost();
        int port = uri.getPort();
        if(port == -1){
            switch (this.scheme){
                case "https":
                    port = 443;
                    break;
                case "http":
                    port = 80;
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        }
        this.port = port;
    }

    public String getScheme() {
        return scheme;
    }

    public String getServerName() {
        return serverName;
    }

    public int getPort() {
        return port;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Origin)) return false;

        Origin origin = (Origin) o;

        if (port != origin.port) return false;
        if (!scheme.equals(origin.scheme)) return false;
        return serverName.equals(origin.serverName);
    }

    @Override
    public int hashCode() {
        int result = scheme.hashCode();
        result = 31 * result + serverName.hashCode();
        result = 31 * result + port;
        return result;
    }
}
