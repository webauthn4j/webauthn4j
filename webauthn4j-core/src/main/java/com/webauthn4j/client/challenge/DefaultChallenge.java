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

package com.webauthn4j.client.challenge;

import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

public class DefaultChallenge implements Challenge {
    private final byte[] value;

    /**
     * Creates a new instance
     *
     * @param value the value of the challenge
     */
    public DefaultChallenge(byte[] value) {
        AssertUtil.notNull(value, "value cannot be null");
        this.value = value;
    }

    public DefaultChallenge(String base64urlString) {
        AssertUtil.notNull(base64urlString, "base64urlString cannot be null");
        this.value = Base64UrlUtil.decode(base64urlString);
    }

    public DefaultChallenge() {
        UUID uuid = UUID.randomUUID();
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        this.value = ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
    }

    @Override
    public byte[] getValue() {
        return this.value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DefaultChallenge that = (DefaultChallenge) o;
        return Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }
}
