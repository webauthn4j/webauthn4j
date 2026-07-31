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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class CertificationType {

    public static final CertificationType FIPS_CMVP_2 = new CertificationType("FIPS-CMVP-2");
    public static final CertificationType FIPS_CMVP_3 = new CertificationType("FIPS-CMVP-3");
    public static final CertificationType FIPS_CMVP_2_PHY = new CertificationType("FIPS-CMVP-2-PHY");
    public static final CertificationType FIPS_CMVP_3_PHY = new CertificationType("FIPS-CMVP-3-PHY");
    public static final CertificationType CC_EAL = new CertificationType("CC-EAL");
    public static final CertificationType FIDO = new CertificationType("FIDO");
    public static final CertificationType CCN_CPSTIC = new CertificationType("CCN-CPSTIC");

    private final String value;

    public CertificationType(@NotNull String value) {
        this.value = value;
    }

    @JsonCreator
    public static @NotNull CertificationType create(@NotNull String value) {
        return new CertificationType(value);
    }

    @JsonValue
    public @NotNull String getValue() {
        return value;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertificationType that = (CertificationType) o;
        return value.equals(that.value);
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
