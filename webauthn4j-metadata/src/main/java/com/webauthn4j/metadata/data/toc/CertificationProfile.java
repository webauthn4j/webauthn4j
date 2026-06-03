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

package com.webauthn4j.metadata.data.toc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

/**
 * Represents a supported certification profile for an authenticator.
 * The set of profiles is defined by the FIDO Alliance Authenticator Certification Policy
 * and is not a closed enumeration.
 *
 * @see <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-certificationprofiles">
 * §3.1.3. StatusReport - certificationProfiles</a>
 */
public class CertificationProfile {

    public static final CertificationProfile CONSUMER = new CertificationProfile("consumer");
    public static final CertificationProfile ENTERPRISE = new CertificationProfile("enterprise");

    @NotNull
    private final String value;

    @JsonCreator
    public CertificationProfile(@NotNull String value) {
        this.value = value;
    }

    @JsonValue
    @NotNull
    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertificationProfile that = (CertificationProfile) o;
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
