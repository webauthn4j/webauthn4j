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

package com.webauthn4j.data.x500;

import com.webauthn4j.util.AssertUtil;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

public class X500Name extends AbstractList<Attributes> implements Serializable {

    private final int size;
    private Attributes[] attributes;

    public X500Name(String value) {
        this(Arrays.stream(value.split(","))
                .map(Attributes::new)
                .collect(Collectors.toList()));
    }

    public X500Name(List<Attributes> attributes) {
        AssertUtil.notNull(attributes, "attributes must not be null");
        this.size = attributes.size();
        this.attributes = attributes.toArray(new Attributes[this.size]);
    }

    public X500Name() {
        this(Collections.emptyList());
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public Attributes get(int index) {
        return attributes[index];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        X500Name that = (X500Name) o;
        return size == that.size &&
                Arrays.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), size);
        result = 31 * result + Arrays.hashCode(attributes);
        return result;
    }

}
