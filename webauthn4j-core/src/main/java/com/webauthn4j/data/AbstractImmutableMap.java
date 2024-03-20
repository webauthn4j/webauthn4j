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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;

public abstract class AbstractImmutableMap<K, V> extends AbstractMap<K, V> {

    private final HashMap<K, V> map;
    private transient Set<Entry<K, V>> cachedEntrySet;

    @JsonCreator
    protected AbstractImmutableMap(@NonNull Map<K, V> map) {
        AssertUtil.notNull(map, "map must not be null");
        this.map = new HashMap<>(map);
    }

    @Override
    public @NonNull Set<Entry<K, V>> entrySet() {
        if (this.cachedEntrySet == null) {
            this.cachedEntrySet = Collections.unmodifiableMap(map).entrySet();
        }
        return this.cachedEntrySet;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AbstractImmutableMap<?, ?> that = (AbstractImmutableMap<?, ?>) o;
        return Objects.equals(map, that.map);
    }

    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), map);
    }
}