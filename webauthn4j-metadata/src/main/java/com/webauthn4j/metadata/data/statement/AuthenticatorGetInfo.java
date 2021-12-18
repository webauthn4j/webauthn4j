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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataAAGUIDRelaxedDeserializer;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;
import java.util.Objects;

public class AuthenticatorGetInfo {

    @NonNull
    private final List<String> versions;
    @Nullable
    private final List<String> extensions;
    @NonNull
    @JsonDeserialize(using = MetadataAAGUIDRelaxedDeserializer.class)
    private final AAGUID aaguid;
    @Nullable
    private final Options options;
    @Nullable
    private final Integer maxMsgSize;
    @Nullable
    private final List<PinProtocolVersion> pinProtocols;

    @JsonCreator
    public AuthenticatorGetInfo(
            @JsonProperty("versions") List<String> versions,
            @JsonProperty("extensions") List<String> extensions,
            @JsonProperty("aaguid") AAGUID aaguid,
            @JsonProperty("options") Options options,
            @JsonProperty("maxMsgSize") Integer maxMsgSize,
            @JsonProperty("pinProtocols") List<PinProtocolVersion> pinProtocols) {
        this.versions = versions;
        this.extensions = extensions;
        this.aaguid = aaguid;
        this.options = options;
        this.maxMsgSize = maxMsgSize;
        this.pinProtocols = pinProtocols;
    }

    public List<String> getVersions() {
        return versions;
    }

    public List<String> getExtensions() {
        return extensions;
    }

    public AAGUID getAaguid() {
        return aaguid;
    }

    public Options getOptions() {
        return options;
    }

    public Integer getMaxMsgSize() {
        return maxMsgSize;
    }

    public List<PinProtocolVersion> getPinProtocols() {
        return pinProtocols;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorGetInfo that = (AuthenticatorGetInfo) o;
        return versions.equals(that.versions) && Objects.equals(extensions, that.extensions) && aaguid.equals(that.aaguid) && Objects.equals(options, that.options) && Objects.equals(maxMsgSize, that.maxMsgSize) && Objects.equals(pinProtocols, that.pinProtocols);
    }

    @Override
    public int hashCode() {
        return Objects.hash(versions, extensions, aaguid, options, maxMsgSize, pinProtocols);
    }

    public static class Options {

        @JsonProperty("plat")
        private final PlatformOption plat;
        @JsonProperty("rk")
        private final ResidentKeyOption rk;
        @JsonProperty("clientPIN")
        private final ClientPINOption clientPIN;
        @JsonProperty("up")
        private final UserPresenceOption up;
        @JsonProperty("uv")
        private final UserVerificationOption uv;

        @JsonCreator
        public Options(
                @JsonProperty("plat") PlatformOption plat,
                @JsonProperty("rk") ResidentKeyOption rk,
                @JsonProperty("clientPIN") ClientPINOption clientPIN,
                @JsonProperty("up") UserPresenceOption up,
                @JsonProperty("uv") UserVerificationOption uv) {
            this.plat = plat;
            this.rk = rk;
            this.clientPIN = clientPIN;
            this.up = up;
            this.uv = uv;
        }

        public PlatformOption getPlat() {
            return plat;
        }

        public ResidentKeyOption getRk() {
            return rk;
        }

        public ClientPINOption getClientPIN() {
            return clientPIN;
        }

        public UserPresenceOption getUp() {
            return up;
        }

        public UserVerificationOption getUv() {
            return uv;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Options options = (Options) o;
            return Objects.equals(plat, options.plat) && Objects.equals(rk, options.rk) && Objects.equals(clientPIN, options.clientPIN) && Objects.equals(up, options.up) && Objects.equals(uv, options.uv);
        }

        @Override
        public int hashCode() {
            return Objects.hash(plat, rk, clientPIN, up, uv);
        }

        private static class PlatformOption {

            public static final PlatformOption PLATFORM = new PlatformOption(true);
            public static final PlatformOption CROSS_PLATFORM = new PlatformOption(false);
            public static final PlatformOption NULL = null;

            private final boolean value;

            @JsonCreator
            public PlatformOption(boolean value){
                this.value = value;
            }

            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                PlatformOption that = (PlatformOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        private static class ResidentKeyOption {

            public static final ResidentKeyOption SUPPORTED = new ResidentKeyOption(true);
            public static final ResidentKeyOption NOT_SUPPORTED = new ResidentKeyOption(false);
            public static final ResidentKeyOption NULL = null;

            private final boolean value;

            @JsonCreator
            public ResidentKeyOption(boolean value){
                this.value = value;
            }

            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                ResidentKeyOption that = (ResidentKeyOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        private static class ClientPINOption {

            public static final ClientPINOption SET = new ClientPINOption(true);
            public static final ClientPINOption NOT_SET = new ClientPINOption(false);
            public static final ClientPINOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public ClientPINOption(boolean value){
                this.value = value;
            }

            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                ClientPINOption that = (ClientPINOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        private static class UserPresenceOption {

            public static final UserPresenceOption SUPPORTED = new UserPresenceOption(true);
            public static final UserPresenceOption NOT_SUPPORTED = new UserPresenceOption(false);
            public static final UserPresenceOption NULL = null;

            private final boolean value;

            @JsonCreator
            public UserPresenceOption(boolean value){
                this.value = value;
            }

            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UserPresenceOption that = (UserPresenceOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        private static class UserVerificationOption {

            public static final UserVerificationOption READY = new UserVerificationOption(true);
            public static final UserVerificationOption NOT_READY = new UserVerificationOption(false);
            public static final UserVerificationOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public UserVerificationOption(boolean value){
                this.value = value;
            }

            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UserVerificationOption that = (UserVerificationOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }
    }


    public static class PinProtocolVersion {

        public static final PinProtocolVersion VERSION_1 = new PinProtocolVersion(1);

        private final int value;

        @JsonCreator
        public PinProtocolVersion(int value){
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PinProtocolVersion that = (PinProtocolVersion) o;
            return value == that.value;
        }

        @Override
        public int hashCode() {
            return Objects.hash(value);
        }
    }


}
