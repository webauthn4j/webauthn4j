/*
 * Copyright 2018 the original author or authors.
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

import com.webauthn4j.util.CollectionUtil;

import java.util.AbstractSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class KeyProtections extends AbstractSet<KeyProtection> {

    private Set<KeyProtection> keyProtections;

    public KeyProtections(int value) {
        Set<KeyProtection> set = new HashSet<>();
        if ((value & KeyProtection.SOFTWARE.getValue()) > 0) {
            set.add(KeyProtection.SOFTWARE);
        }
        if ((value & KeyProtection.HARDWARE.getValue()) > 0) {
            set.add(KeyProtection.HARDWARE);
        }
        if ((value & KeyProtection.TEE.getValue()) > 0) {
            set.add(KeyProtection.TEE);
        }
        if ((value & KeyProtection.SECURE_ELEMENT.getValue()) > 0) {
            set.add(KeyProtection.SECURE_ELEMENT);
        }
        if ((value & KeyProtection.REMOTE_HANDLE.getValue()) > 0) {
            set.add(KeyProtection.REMOTE_HANDLE);
        }
        keyProtections = CollectionUtil.unmodifiableSet(set);
    }

    @Override
    public Iterator<KeyProtection> iterator() {
        return keyProtections.iterator();
    }

    @Override
    public int size() {
        return keyProtections.size();
    }
}
