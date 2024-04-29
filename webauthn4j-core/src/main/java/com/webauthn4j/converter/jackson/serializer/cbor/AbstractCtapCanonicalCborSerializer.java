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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public abstract class AbstractCtapCanonicalCborSerializer<T> extends StdSerializer<T> {

    private final transient List<FieldSerializationRule<T, ?>> rules;

    protected AbstractCtapCanonicalCborSerializer(@NotNull Class<T> t, @NotNull List<FieldSerializationRule<T, ?>> rules) {
        super(t);
        this.rules = rules;
    }

    @Override
    public void serialize(@NotNull T value, @NotNull JsonGenerator gen, @NotNull SerializerProvider provider) throws IOException {
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
        @NotNull
        private final Object name;
        @Nullable
        private final Object value;

        public KeyValue(@NotNull Object name, @Nullable Object value) {
            this.name = name;
            this.value = value;
        }
    }

    public static class FieldSerializationRule<T, R> {

        @NotNull
        private final Object name;
        @NotNull
        private final Function<T, R> getter;

        public FieldSerializationRule(int name, @NotNull Function<T, @Nullable R> getter) {
            this.name = name;
            this.getter = getter;
        }

        public FieldSerializationRule(@NotNull String name, @NotNull Function<T, @Nullable R> getter) {
            this.name = name;
            this.getter = getter;
        }

        public @NotNull Object getName() {
            return name;
        }

        public @NotNull Function<T, @NotNull R> getGetter() {
            return getter;
        }
    }


}
