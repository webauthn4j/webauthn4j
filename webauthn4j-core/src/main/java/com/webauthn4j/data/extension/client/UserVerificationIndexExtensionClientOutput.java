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

package com.webauthn4j.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.data.extension.AbstractExtensionOutput;

import java.util.Arrays;

/**
 * @deprecated
 */
@Deprecated
public class UserVerificationIndexExtensionClientOutput
        extends AbstractExtensionOutput<byte[]>
        implements RegistrationExtensionClientOutput<byte[]>, AuthenticationExtensionClientOutput<byte[]> {

    public static final String ID = "uvi";

    @JsonCreator
    public UserVerificationIndexExtensionClientOutput(byte[] value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractExtensionOutput<?> that = (AbstractExtensionOutput<?>) o;
        return Arrays.equals(this.getValue(), (byte[]) that.getValue());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getValue());
    }

}
