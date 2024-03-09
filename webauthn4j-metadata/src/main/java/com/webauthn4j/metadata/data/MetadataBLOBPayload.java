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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

public class MetadataBLOBPayload {
    @Nullable
    private final String legalHeader;
    @NonNull
    private final Integer no;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @NonNull
    private final LocalDate nextUpdate;
    @NonNull
    private final List<MetadataBLOBPayloadEntry> entries;

    public MetadataBLOBPayload(
            @JsonProperty("legalHeader") @Nullable String legalHeader,
            @JsonProperty("no") @NonNull Integer no,
            @JsonProperty("nextUpdate") @NonNull LocalDate nextUpdate,
            @JsonProperty("entries") @NonNull List<MetadataBLOBPayloadEntry> entries) {
        this.legalHeader = legalHeader;
        this.no = no;
        this.nextUpdate = nextUpdate;
        this.entries = entries;
    }

    @Nullable
    public String getLegalHeader() {
        return legalHeader;
    }

    @NonNull
    public Integer getNo() {
        return no;
    }

    @NonNull
    public LocalDate getNextUpdate() {
        return nextUpdate;
    }

    @NonNull
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
