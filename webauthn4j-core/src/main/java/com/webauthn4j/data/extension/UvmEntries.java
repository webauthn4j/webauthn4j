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

package com.webauthn4j.data.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;

public class UvmEntries extends AbstractList<UvmEntry> {

    private final int size;
    private final UvmEntry[] array;

    @JsonCreator
    public UvmEntries(@NonNull List<UvmEntry> value) {
        AssertUtil.notNull(value, "value must not be null");
        this.size = value.size();
        this.array = value.toArray(new UvmEntry[this.size]);
    }

    public UvmEntries() {
        this(Collections.emptyList());
    }

    @Override
    public @NonNull UvmEntry get(int index) {
        return array[index];
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        UvmEntries that = (UvmEntries) o;
        return size == that.size &&
                Arrays.equals(array, that.array);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), size);
        result = 31 * result + Arrays.hashCode(array);
        return result;
    }
}
