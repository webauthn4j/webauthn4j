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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.util.Arrays;
import java.util.Objects;

/**
 * The supported attachment hint type(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authenticator-attachment-hints">§3.4 Authenticator Attachment Hints</a>
 */
public enum AttachmentHint {

    INTERNAL(0x0001, "internal"),
    EXTERNAL(0x0002, "external"),
    WIRED(0x0004, "wired"),
    WIRELESS(0x0008, "wireless"),
    NFC(0x0010, "nfc"),
    BLUETOOTH(0x0020, "bluetooth"),
    NETWORK(0x0040, "network"),
    READY(0x0080, "ready"),
    WIFI_DIRECT(0x0100, "wifi_direct");

    private final long value;
    private final String string;

    AttachmentHint(long value, String string) {
        this.value = value;
        this.string = string;
    }

    public static AttachmentHint create(long value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        return Arrays.stream(AttachmentHint.values()).filter(item -> item.value == value)
                .findFirst().orElseThrow(()->new IllegalArgumentException("value '" + value + "' is out of range"));
    }

    public static AttachmentHint create(String value) {
        return Arrays.stream(AttachmentHint.values()).filter(item -> Objects.equals(item.string, value))
                .findFirst().orElseThrow(()->new IllegalArgumentException("value '" + value + "' is out of range"));
    }

    public long getValue() {
        return value;
    }

    @Override
    public String toString() {
        return string;
    }
}
