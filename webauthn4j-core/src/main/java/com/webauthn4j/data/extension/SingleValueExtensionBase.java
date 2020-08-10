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

package com.webauthn4j.data.extension;

import java.io.Serializable;
import java.util.Objects;

public abstract class SingleValueExtensionBase<T extends Serializable> {

    private final T value;

    public SingleValueExtensionBase(T value) {
        this.value = value;
    }

    public SingleValueExtensionBase() {
        this.value = null;
    }

    public T getValue(String key) {
        if(!key.equals(getIdentifier())){
            throw new IllegalArgumentException(String.format("%s is the only valid key.", getIdentifier()));
        }
        return value;
    }

    protected abstract String getIdentifier();

    protected T getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SingleValueExtensionBase<?> that = (SingleValueExtensionBase<?>) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
