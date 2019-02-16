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

package com.webauthn4j.util;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.io.Serializable;
import java.util.*;

public abstract class AbstractImmutableMap<K, V> extends AbstractMap<K, V> implements Serializable {

    private final HashMap<K, V> map;
    private transient Set<Entry<K, V>> cachedEntrySet;

    @SuppressWarnings("unchecked")
    @JsonCreator
    public AbstractImmutableMap(Map<K, V> map) {
        AssertUtil.notNull(map, "map must not be null");
        this.map = new HashMap<>(map);
    }

    public AbstractImmutableMap() {
        this(Collections.emptyMap());
    }

    @Override
    public Set<Entry<K, V>> entrySet() {
        if(this.cachedEntrySet == null){
            this.cachedEntrySet = Collections.unmodifiableMap(map).entrySet();
        }
        return this.cachedEntrySet;
    }

    @Override
    public boolean equals(Object o) {
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