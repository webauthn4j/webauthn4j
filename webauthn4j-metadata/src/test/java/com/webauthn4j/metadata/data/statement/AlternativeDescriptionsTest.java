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

package com.webauthn4j.metadata.data.statement;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;

class AlternativeDescriptionsTest {

    @Test
    void put_test() {
        AlternativeDescriptions target = new AlternativeDescriptions();
        assertThrows(UnsupportedOperationException.class,
                () -> target.put("key", "value")
        );
    }

    @Test
    void entrySet_remove_test() {
        Map<String, String> source = new HashMap<>();
        source.put("key", "value");
        AlternativeDescriptions target = new AlternativeDescriptions(source);
        assertThrows(UnsupportedOperationException.class,
                () -> target.entrySet().remove(target.entrySet().iterator().next())
        );
    }

}
