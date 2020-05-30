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

package com.webauthn4j.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.UnsignedNumberUtil;

/**
 * The supported attachment hint type(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authenticator-attachment-hints">§3.4 Authenticator Attachment Hints</a>
 */
public enum AttachmentHint {

    INTERNAL(0x0001),
    EXTERNAL(0x0002),
    WIRED(0x0004),
    WIRELESS(0x0008),
    NFC(0x0010),
    BLUETOOTH(0x0020),
    NETWORK(0x0040),
    READY(0x0080),
    WIFI_DIRECT(0x0100);

    private final long value;

    AttachmentHint(long value) {
        this.value = value;
    }

    public static AttachmentHint create(long value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        if (value == 0x0001) {
            return INTERNAL;
        } else if (value == 0x0002) {
            return EXTERNAL;
        } else if (value == 0x0004) {
            return WIRED;
        } else if (value == 0x0008) {
            return WIRELESS;
        } else if (value == 0x0010) {
            return NFC;
        } else if (value == 0x0020) {
            return BLUETOOTH;
        } else if (value == 0x0040) {
            return NETWORK;
        } else if (value == 0x0080) {
            return READY;
        } else if (value == 0x0100) {
            return WIFI_DIRECT;
        }
        throw new IllegalArgumentException("value '" + value + "' is out of range");
    }

    @JsonCreator
    private static AttachmentHint deserialize(long value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AttachmentHint.class);
        }
    }

    @JsonValue
    public long getValue() {
        return value;
    }

}
