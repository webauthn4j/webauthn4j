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

    public enum OriginType {
        WEB,
        APK_KEY_HASH
    }

    private static final String SCHEME_HTTPS = "https";
    private static final String SCHEME_HTTP = "http";
    private static final String SCHEME_APK_KEY_HASH_SHA1 = "android:apk-key-hash";
    private static final String SCHEME_APK_KEY_HASH_SHA256 = "android:apk-key-hash-sha256";

    private static final String SCHEME_PREFIX_HTTPS = SCHEME_HTTPS + ":";
    private static final String SCHEME_PREFIX_HTTP = SCHEME_HTTP + ":";
    private static final String SCHEME_PREFIX_APK_KEY_HASH_SHA1 = SCHEME_APK_KEY_HASH_SHA1 + ":";
    private static final String SCHEME_PREFIX_APK_KEY_HASH_SHA256 = SCHEME_APK_KEY_HASH_SHA256 + ":";

    private static final String SCHEME_WEB_ERROR_MESSAGE = "scheme must be 'http' or 'https'";
    private static final String SCHEME_APK_SIGNING_ERROR_MESSAGE = "scheme must be '" + SCHEME_APK_KEY_HASH_SHA1 + "' or "
            + "'" + SCHEME_APK_KEY_HASH_SHA256 + "'";

    private static final String SCHEME_ERROR_MESSAGE = "scheme must be 'http' or 'https' or '" + SCHEME_APK_KEY_HASH_SHA1 + "' or "
            + "'" + SCHEME_APK_KEY_HASH_SHA256 + "'";

    private String scheme;
    private String host;
    private int port;
    private String apkSigningCertHash;
    private OriginType originType;

    public Origin(String scheme, String host, int port) {
        if (!Objects.equals(SCHEME_HTTPS, scheme) && !Objects.equals(SCHEME_HTTP, scheme)) {
            throw new IllegalArgumentException(SCHEME_WEB_ERROR_MESSAGE);
        }

        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.apkSigningCertHash = null;
        this.originType = OriginType.WEB;
    }

    public Origin(String scheme, String apkSigningCertHash) {
        if (!Objects.equals(SCHEME_APK_KEY_HASH_SHA1, scheme) && !Objects.equals(SCHEME_APK_KEY_HASH_SHA256, scheme)) {
            throw new IllegalArgumentException(SCHEME_APK_SIGNING_ERROR_MESSAGE);
        }

        this.scheme = scheme;
        this.host = null;
        this.port = -1;
        this.apkSigningCertHash = apkSigningCertHash;
        this.originType = OriginType.APK_KEY_HASH;
    }

    public Origin(String originStr) {
        if (originStr == null){
            throw new IllegalArgumentException("originStr must not be null");
        }
        final String trimmedOriginStr = originStr.trim();
        if (trimmedOriginStr.startsWith(SCHEME_PREFIX_HTTP) || trimmedOriginStr.startsWith(SCHEME_PREFIX_HTTPS)) {
            URI uri = URI.create(originStr);
            this.apkSigningCertHash = null;
            this.originType = OriginType.WEB;
            this.host = uri.getHost();
            this.scheme = uri.getScheme();
            int originPort = uri.getPort();

            if (originPort == -1) {
                switch (this.scheme) {
                    case SCHEME_HTTPS:
                        originPort = 443;
                        break;
                    case SCHEME_HTTP:
                        originPort = 80;
                        break;
                    default:
                        throw new IllegalArgumentException(SCHEME_WEB_ERROR_MESSAGE);
                }
            }
            this.port = originPort;
        } else if (trimmedOriginStr.startsWith(SCHEME_PREFIX_APK_KEY_HASH_SHA1)){
            this.host = null;
            this.scheme = SCHEME_APK_KEY_HASH_SHA1;
            this.port = -1;
            this.apkSigningCertHash = trimmedOriginStr.substring(SCHEME_PREFIX_APK_KEY_HASH_SHA1.length());
            this.originType = OriginType.APK_KEY_HASH;
        } else if (trimmedOriginStr.startsWith(SCHEME_PREFIX_APK_KEY_HASH_SHA256)){
            this.host = null;
            this.scheme = SCHEME_APK_KEY_HASH_SHA256;
            this.port = -1;
            this.apkSigningCertHash = trimmedOriginStr.substring(SCHEME_PREFIX_APK_KEY_HASH_SHA256.length());
            this.originType = OriginType.APK_KEY_HASH;
        }
        else {
            throw new IllegalArgumentException(SCHEME_ERROR_MESSAGE);
        }
    }

    public static Origin create(String value) {
        try {
            return new Origin(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("value is out of range: " + e.getMessage());
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

    public int getPort() {
        return port;
    }

    public String getApkSigningCertHash() {
        return apkSigningCertHash;
    }

    public OriginType getOriginType() {
        return originType;
    }

    @JsonValue
    @Override
    public String toString() {
        switch (this.originType) {
            case APK_KEY_HASH: {
                return this.scheme + ":" + this.apkSigningCertHash;
            }
            case WEB: {
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
            default: {
                throw new IllegalStateException("Bad origin type :" + this.originType);
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Origin)) return false;

        Origin origin = (Origin) o;
        if (this.originType != origin.originType) return false;

        switch (this.originType){
            case APK_KEY_HASH:{
                if (!scheme.equals(origin.scheme)) return false;
                return this.apkSigningCertHash.equals(origin.apkSigningCertHash);
            }
            case WEB:{
                if (port != origin.port) return false;
                //noinspection SimplifiableIfStatement
                if (!scheme.equals(origin.scheme)) return false;
                return host.equals(origin.host);
            }
            default:{
                throw new IllegalStateException("Bad origin type :" + this.originType);
            }
        }
    }

    @Override
    public int hashCode() {
        switch (this.originType) {
            case APK_KEY_HASH: {
                int result = scheme.hashCode();
                result = 31 * result + apkSigningCertHash.hashCode();
                return result;
            }
            case WEB:{
                int result = scheme.hashCode();
                result = 31 * result + host.hashCode();
                result = 31 * result + port;
                return result;
            }
            default:
                throw new IllegalStateException("Bad origin type :" + this.originType);
        }
    }
}
