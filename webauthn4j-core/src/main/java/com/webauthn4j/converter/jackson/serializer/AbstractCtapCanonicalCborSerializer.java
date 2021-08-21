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

package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public abstract class AbstractCtapCanonicalCborSerializer<T> extends StdSerializer<T> {

    private final transient List<FieldSerializationRule<T, ?>> rules;

    protected AbstractCtapCanonicalCborSerializer(@NonNull Class<T> t, @NonNull List<FieldSerializationRule<T, ?>> rules) {
        super(t);
        this.rules = rules;
    }

    @Override
    public void serialize(@NonNull T value, @NonNull JsonGenerator gen, @NonNull SerializerProvider provider) throws IOException {
        List<KeyValue> nonNullValues =
                rules.stream()
                        .map(rule -> {
                            Object fieldValue = rule.getGetter().apply(value);
                            return new KeyValue(rule.getName(), fieldValue);
                        })
                        .filter(item -> item.value != null)
                        .collect(Collectors.toList());
        ((CBORGenerator) gen).writeStartObject(nonNullValues.size()); // This is important to write finite length map

        for (KeyValue nonNullValue : nonNullValues) {
            if (nonNullValue.name instanceof String) {
                gen.writeFieldName((String) nonNullValue.name);
            }
            else {
                gen.writeFieldId((int) nonNullValue.name);
            }
            gen.writeObject(nonNullValue.value);
        }

        gen.writeEndObject();
    }

    private static class KeyValue {
        @NonNull
        private final Object name;
        @Nullable
        private final Object value;

        public KeyValue(@NonNull Object name, @Nullable Object value) {
            this.name = name;
            this.value = value;
        }
    }

    public static class FieldSerializationRule<T, R> {

        @NonNull
        private final Object name;
        @NonNull
        private final Function<T, R> getter;

        public FieldSerializationRule(int name, @NonNull Function<T, @Nullable R> getter) {
            this.name = name;
            this.getter = getter;
        }

        public FieldSerializationRule(@NonNull String name, @NonNull Function<T, @Nullable R> getter) {
            this.name = name;
            this.getter = getter;
        }

        public @NonNull Object getName() {
            return name;
        }

        public @NonNull Function<T, @NonNull R> getGetter() {
            return getter;
        }
    }


}
