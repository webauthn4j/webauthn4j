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

package com.webauthn4j.client;

import java.io.Serializable;
import java.net.URI;

/**
 * Origin
 */
public class Origin implements Serializable {

    private static final String SCHEME_HTTPS = "https";
    private static final String SCHEME_HTTP = "http";

    private String scheme;
    private String host;
    private int port;

    public Origin(String scheme, String host, int port) {
        if (!scheme.equals(SCHEME_HTTPS) && !scheme.equals(SCHEME_HTTP)) {
            throw new IllegalArgumentException("scheme must be 'http' or 'https'");
        }

        this.scheme = scheme;
        this.host = host;
        this.port = port;
    }

    public Origin(String originUrl) {
        URI uri = URI.create(originUrl);
        this.scheme = uri.getScheme();
        this.host = uri.getHost();
        int originPort = uri.getPort();

        if (!scheme.equals(SCHEME_HTTPS) && !scheme.equals(SCHEME_HTTP)) {
            throw new IllegalArgumentException("scheme must be 'http' or 'https'");
        }

        if (originPort == -1) {
            switch (this.scheme) {
                case SCHEME_HTTPS:
                    originPort = 443;
                    break;
                case SCHEME_HTTP:
                    originPort = 80;
                    break;
                default:
                    throw new IllegalStateException();
            }
        }
        this.port = originPort;
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    @Override
    public String toString() {
        String result = this.scheme + "://" + this.host;
        switch (this.scheme) {
            case SCHEME_HTTPS:
                if (this.port != 443) {
                    result += ":" + this.port;
                }
                break;
            case SCHEME_HTTP:
                if (this.port != 80) {
                    result += ":" + this.port;
                }
                break;
            default:
                throw new IllegalStateException();
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Origin)) return false;

        Origin origin = (Origin) o;

        if (port != origin.port) return false;
        if (!scheme.equals(origin.scheme)) return false;
        return host.equals(origin.host);
    }

    @Override
    public int hashCode() {
        int result = scheme.hashCode();
        result = 31 * result + host.hashCode();
        result = 31 * result + port;
        return result;
    }
}
