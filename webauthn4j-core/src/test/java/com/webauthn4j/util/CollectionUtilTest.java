package com.webauthn4j.util;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class CollectionUtilTest {

    @Test
    void unmodifiableList_should_not_be_affected_by_modification_to_original() {
        List<String> original = new ArrayList<>(List.of("a", "b"));
        List<String> unmodifiable = CollectionUtil.unmodifiableList(original);

        original.add("c");

        assertThat(unmodifiable).containsExactly("a", "b");
    }

    @Test
    void unmodifiableSet_should_not_be_affected_by_modification_to_original() {
        Set<String> original = new HashSet<>(Set.of("a", "b"));
        Set<String> unmodifiable = CollectionUtil.unmodifiableSet(original);

        original.add("c");

        assertThat(unmodifiable).containsExactlyInAnyOrder("a", "b");
    }

    @Test
    void unmodifiableMap_should_not_be_affected_by_modification_to_original() {
        Map<String, String> original = new HashMap<>(Map.of("k1", "v1"));
        Map<String, String> unmodifiable = CollectionUtil.unmodifiableMap(original);

        original.put("k2", "v2");

        assertThat(unmodifiable).containsOnlyKeys("k1").hasSize(1);
    }
}
