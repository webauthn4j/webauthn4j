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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.util.ArrayUtil;
import org.jetbrains.annotations.NotNull;
import java.util.Arrays;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardDeserializer;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardSerializer;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = ModuleNotRegisteredGuardSerializer.class)
@JsonDeserialize(using = ModuleNotRegisteredGuardDeserializer.class)
public enum TPMGenerated {

    TPM_GENERATED_VALUE(new byte[]{(byte) 0xff, (byte) 0x54, (byte) 0x43, (byte) 0x47});

    private final byte[] value;

    TPMGenerated(@NotNull byte[] value) {
        this.value = value;
    }

    public static @NotNull TPMGenerated create(@NotNull byte[] value) {
        if (Arrays.equals(value, TPM_GENERATED_VALUE.value)) {
            return TPM_GENERATED_VALUE;
        }
        else {
            throw new IllegalArgumentException("value is out of range");
        }
    }

    public @NotNull byte[] getValue() {
        return ArrayUtil.clone(value);
    }
}
