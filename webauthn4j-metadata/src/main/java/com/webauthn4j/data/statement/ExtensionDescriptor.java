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
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Objects;

/**
 * This descriptor contains an extension supported by the authenticator.
 */
public class ExtensionDescriptor implements Serializable {

    private final String id;
    private final Integer tag;
    private final String data;
    private final Boolean failIfUnknown;

    @JsonCreator
    public ExtensionDescriptor(
            @JsonProperty("id") String id,
            @JsonProperty("tag") Integer tag,
            @JsonProperty("data") String data,
            @JsonProperty("fail_if_unknown") Boolean failIfUnknown) {
        this.id = id;
        this.tag = tag;
        this.data = data;
        this.failIfUnknown = failIfUnknown;
    }

    @JsonGetter
    public String getId() {
        return id;
    }

    @JsonGetter
    public Integer getTag() {
        return tag;
    }

    @JsonGetter
    public String getData() {
        return data;
    }

    @JsonGetter("fail_if_unknown")
    public Boolean getFailIfUnknown() {
        return failIfUnknown;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExtensionDescriptor that = (ExtensionDescriptor) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(tag, that.tag) &&
                Objects.equals(data, that.data) &&
                Objects.equals(failIfUnknown, that.failIfUnknown);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, tag, data, failIfUnknown);
    }
}
