/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import java.io.Serializable;
import java.net.URI;
import java.util.Objects;

/**
 * {@link Origin} contains the fully qualified origin of the requester, as provided to the authenticator
 * by the client.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dom-collectedclientdata-origin">§5.10.1. Client Data Used in WebAuthn Signatures - origin</a>
 */
public class Origin implements Serializable {

    private static final String SCHEME_HTTPS = "https";
    private static final String SCHEME_HTTP = "http";
    private static final String SCHEME_ERROR_MESSAGE = "scheme must be 'http' or 'https'";

    private String scheme;
    private String host;
    private Integer port;
    private String schemeSpecificPart;
    private boolean explicitPortNotation;

    /**
     * @deprecated this constructor will be removed before GA release.
     */
    @Deprecated
    public Origin(String scheme, String host, int port) {
        if (!Objects.equals(SCHEME_HTTPS, scheme) && !Objects.equals(SCHEME_HTTP, scheme)) {
            throw new IllegalArgumentException(SCHEME_ERROR_MESSAGE);
        }

        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.schemeSpecificPart = "//" + host + ":" + port;
    }

    public Origin(String originUrl) {
        URI uri = URI.create(originUrl);
        this.scheme = uri.getScheme();
        if(SCHEME_HTTPS.equals(this.scheme) || SCHEME_HTTP.equals(this.scheme)){
            this.host = uri.getHost();
            int originPort = uri.getPort();
            if (originPort == -1) {
                explicitPortNotation = false;
                if (SCHEME_HTTPS.equals(this.scheme)) {
                    originPort = 443;
                }
                else { // SCHEME_HTTP
                    originPort = 80;
                }
            }
            else {
                explicitPortNotation = true;
            }
            this.port = originPort;
            this.schemeSpecificPart = null;
        }
        else {
            this.explicitPortNotation = uri.getPort() != -1;
            this.port = null;
            this.schemeSpecificPart = uri.getSchemeSpecificPart();
        }
    }

    public static Origin create(String value) {
        try {
            return new Origin(value);
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("value is out of range: null", e);
        }
    }

    @JsonCreator
    private static Origin deserialize(String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, Origin.class);
        }
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public Integer getPort() {
        return port;
    }

    public String getSchemeSpecificPart() {
        return schemeSpecificPart;
    }

    @JsonValue
    @Override
    public String toString() {
        if(this.scheme == null){
            return this.schemeSpecificPart;
        }
        String result;
        switch (this.scheme){
            case SCHEME_HTTPS:
            case SCHEME_HTTP:
                result = this.scheme + "://" + this.host;
                if (this.explicitPortNotation) {
                    result += ":" + this.port;
                }
                return result;
            default:
                return this.scheme + ":" + this.schemeSpecificPart;
        }
    }

    @Override
    public boolean equals(Object o) {
        // explicitPortNotation is not taken into count
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Origin origin = (Origin) o;
        if(SCHEME_HTTPS.equals(this.scheme) || SCHEME_HTTP.equals(this.scheme)){
            return Objects.equals(scheme, origin.scheme) &&
                    Objects.equals(host, origin.host) &&
                    Objects.equals(port, origin.port);
        }
        else {
            return Objects.equals(scheme, origin.scheme) &&
                    Objects.equals(schemeSpecificPart, origin.schemeSpecificPart);
        }
    }


    @Override
    public int hashCode() {
        // explicitPortNotation is not taken into count
        if(SCHEME_HTTPS.equals(this.scheme) || SCHEME_HTTP.equals(this.scheme)){
            return Objects.hash(scheme, host, port);
        }
        else {
            return Objects.hash(scheme, schemeSpecificPart);
        }
    }
}
