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

package com.webauthn4j.metadata.legacy.data.toc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.webauthn4j.util.CollectionUtil;

import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

/**
 * Represents the MetadataTOCPayload
 */
@Deprecated
public class MetadataTOCPayload {

    @JsonProperty
    private final String legalHeader;

    @JsonProperty
    private final Integer no;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @JsonProperty
    private final LocalDate nextUpdate;

    @JsonProperty
    private final List<MetadataTOCPayloadEntry> entries;

    @JsonCreator
    public MetadataTOCPayload(
            @JsonProperty("legalHeader") String legalHeader,
            @JsonProperty("no") Integer no,
            @JsonProperty("nextUpdate") LocalDate nextUpdate,
            @JsonProperty("entries") List<MetadataTOCPayloadEntry> entries) {
        this.legalHeader = legalHeader;
        this.no = no;
        this.nextUpdate = nextUpdate;
        this.entries = CollectionUtil.unmodifiableList(entries);
    }

    public String getLegalHeader() {
        return legalHeader;
    }

    public LocalDate getNextUpdate() {
        return nextUpdate;
    }

    public Integer getNo() {
        return no;
    }

    public List<MetadataTOCPayloadEntry> getEntries() {
        return entries;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MetadataTOCPayload that = (MetadataTOCPayload) o;
        return Objects.equals(legalHeader, that.legalHeader) &&
                Objects.equals(no, that.no) &&
                Objects.equals(nextUpdate, that.nextUpdate) &&
                Objects.equals(entries, that.entries);
    }

    @Override
    public int hashCode() {

        return Objects.hash(legalHeader, no, nextUpdate, entries);
    }
}
