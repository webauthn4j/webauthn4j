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

package com.webauthn4j.metadata.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.ext.javatime.deser.LocalDateDeserializer;
import tools.jackson.databind.ext.javatime.ser.LocalDateSerializer;

import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

public class MetadataBLOBPayload {
    @Nullable
    private final String legalHeader;
    @NotNull
    private final Integer no;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @NotNull
    private final LocalDate nextUpdate;
    @NotNull
    private final List<MetadataBLOBPayloadEntry> entries;

    public MetadataBLOBPayload(
            @JsonProperty("legalHeader") @Nullable String legalHeader,
            @JsonProperty("no") @NotNull Integer no,
            @JsonProperty("nextUpdate") @NotNull LocalDate nextUpdate,
            @JsonProperty("entries") @NotNull List<MetadataBLOBPayloadEntry> entries) {
        this.legalHeader = legalHeader;
        this.no = no;
        this.nextUpdate = nextUpdate;
        this.entries = entries;
    }

    @Nullable
    public String getLegalHeader() {
        return legalHeader;
    }

    @NotNull
    public Integer getNo() {
        return no;
    }

    @NotNull
    public LocalDate getNextUpdate() {
        return nextUpdate;
    }

    @NotNull
    public List<MetadataBLOBPayloadEntry> getEntries() {
        return entries;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MetadataBLOBPayload that = (MetadataBLOBPayload) o;
        return Objects.equals(legalHeader, that.legalHeader) && no.equals(that.no) && nextUpdate.equals(that.nextUpdate) && entries.equals(that.entries);
    }

    @Override
    public int hashCode() {
        return Objects.hash(legalHeader, no, nextUpdate, entries);
    }
}
