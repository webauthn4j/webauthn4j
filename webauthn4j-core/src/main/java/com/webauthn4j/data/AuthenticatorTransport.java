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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * Authenticators may implement various transports for communicating with clients.
 * This enumeration defines hints as to how clients might communicate with a particular authenticator in order to
 * obtain an assertion for a specific credential. Note that these hints represent the WebAuthn Relying Party's
 * best belief as to how an authenticator may be reached.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#enumdef-authenticatortransport">
 * §5.10.4. Authenticator Transport Enumeration (enum AuthenticatorTransport)</a>
 */
public class AuthenticatorTransport {

    /**
     * Indicates the respective authenticator can be contacted over removable USB.
     */
    public static final AuthenticatorTransport USB = new AuthenticatorTransport("usb");

    /**
     * Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
     */
    public static final AuthenticatorTransport NFC = new AuthenticatorTransport("nfc");

    /**
     * Indicates the respective authenticator can be contacted over Bluetooth Smart
     * (Bluetooth Low Energy / BLE).
     */
    public static final AuthenticatorTransport BLE = new AuthenticatorTransport("ble");

    /**
     * Indicates the respective authenticator can be contacted using a combination of (often separate) data-transport
     * and proximity mechanisms. This supports, for example, authentication on a desktop computer using a smartphone.
     */
    public static final AuthenticatorTransport HYBRID = new AuthenticatorTransport("hybrid");

    /**
     * Indicates the respective authenticator is contacted using a client device-specific transport.
     * These authenticators are not removable from the client device.
     */
    public static final AuthenticatorTransport INTERNAL = new AuthenticatorTransport("internal");

    private final String value;

    private AuthenticatorTransport(@NonNull String value) {
        this.value = value;
    }

    public static @NonNull AuthenticatorTransport create(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        return new AuthenticatorTransport(value);
    }

    @JsonCreator
    static @NonNull AuthenticatorTransport deserialize(@NonNull String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AuthenticatorTransport.class);
        }
    }

    @JsonValue
    public @NonNull String getValue() {
        return value;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorTransport that = (AuthenticatorTransport) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
