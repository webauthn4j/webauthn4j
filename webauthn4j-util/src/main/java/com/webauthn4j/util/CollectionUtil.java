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

package com.webauthn4j.util;


import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.*;

public class CollectionUtil {

    private CollectionUtil() {
    }

    public static <T> @Nullable List<T> unmodifiableList(@Nullable List<? extends T> list) {
        return list == null ? null : Collections.unmodifiableList(list);
    }

    public static <T> @Nullable Set<T> unmodifiableSet(@Nullable Set<? extends T> set) {
        return set == null ? null : Collections.unmodifiableSet(set);
    }

    @SafeVarargs
    public static <T> @NotNull Set<T> unmodifiableSet(@NotNull T... items) {
        Set<T> set = new HashSet<>(Arrays.asList(items));
        return Collections.unmodifiableSet(set);
    }

    public static <K, V> @Nullable Map<K, V> unmodifiableMap(@Nullable Map<? extends K, ? extends V> map) {
        return map == null ? null : Collections.unmodifiableMap(map);
    }
}
