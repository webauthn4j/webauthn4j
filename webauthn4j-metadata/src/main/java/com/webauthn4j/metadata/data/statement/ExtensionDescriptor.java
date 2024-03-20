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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * This descriptor contains an extension supported by the authenticator.
 */
public class ExtensionDescriptor {

    @NonNull private final String id;
    @Nullable private final Integer tag;
    @Nullable private final String data;
    @NonNull private final Boolean failIfUnknown;

    @JsonCreator
    public ExtensionDescriptor(
            @NonNull @JsonProperty("id") String id,
            @Nullable @JsonProperty("tag") Integer tag,
            @Nullable @JsonProperty("data") String data,
            @NonNull @JsonProperty("fail_if_unknown") Boolean failIfUnknown) {
        this.id = id;
        this.tag = tag;
        this.data = data;
        this.failIfUnknown = failIfUnknown;
    }

    @NonNull
    @JsonGetter
    public String getId() {
        return id;
    }

    @Nullable
    @JsonGetter
    public Integer getTag() {
        return tag;
    }

    @Nullable
    @JsonGetter
    public String getData() {
        return data;
    }

    @NonNull
    @JsonGetter("fail_if_unknown")
    public Boolean getFailIfUnknown() {
        return failIfUnknown;
    }

    @Override
    public boolean equals(@Nullable Object o) {
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
