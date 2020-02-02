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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Objects;

/**
 * The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
 */
public class Version implements Serializable {

    private Integer major;
    private Integer minor;

    @JsonCreator
    public Version(
            @JsonProperty("major") Integer major,
            @JsonProperty("minor") Integer minor) {
        this.major = major;
        this.minor = minor;
    }

    public Integer getMajor() {
        return major;
    }

    public Integer getMinor() {
        return minor;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Version version = (Version) o;
        return Objects.equals(major, version.major) &&
                Objects.equals(minor, version.minor);
    }

    @Override
    public int hashCode() {

        return Objects.hash(major, minor);
    }
}
