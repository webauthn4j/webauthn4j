/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

    public Origin(String originUrl) {
        URI uri = URI.create(originUrl);
        this.scheme = uri.getScheme();
        this.serverName = uri.getHost();
        int originPort = uri.getPort();
        if (originPort == -1) {
            switch (this.scheme) {
                case "https":
                    originPort = 443;
                    break;
                case "http":
                    originPort = 80;
                    break;
                default:
                    throw new IllegalArgumentException();
            }
        }
        this.port = originPort;
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
