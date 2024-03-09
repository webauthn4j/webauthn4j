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

package com.webauthn4j.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

public class CredentialPropertiesOutput {

    final Boolean rk;

    @JsonCreator
    public CredentialPropertiesOutput(@Nullable @JsonProperty("rk") Boolean rk) {
        this.rk = rk;
    }

    public @Nullable Boolean getRk() {
        return rk;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialPropertiesOutput that = (CredentialPropertiesOutput) o;
        return Objects.equals(rk, that.rk);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rk);
    }
}