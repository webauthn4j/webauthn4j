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

import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.util.CollectionUtil;

import java.util.AbstractSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class KeyProtections extends AbstractSet<KeyProtectionType> {

    private final Set<KeyProtectionType> keyProtectionTypes;

    public KeyProtections(int value) {
        Set<KeyProtectionType> set = new HashSet<>();
        if ((value & KeyProtectionType.SOFTWARE.getValue()) > 0) {
            set.add(KeyProtectionType.SOFTWARE);
        }
        if ((value & KeyProtectionType.HARDWARE.getValue()) > 0) {
            set.add(KeyProtectionType.HARDWARE);
        }
        if ((value & KeyProtectionType.TEE.getValue()) > 0) {
            set.add(KeyProtectionType.TEE);
        }
        if ((value & KeyProtectionType.SECURE_ELEMENT.getValue()) > 0) {
            set.add(KeyProtectionType.SECURE_ELEMENT);
        }
        if ((value & KeyProtectionType.REMOTE_HANDLE.getValue()) > 0) {
            set.add(KeyProtectionType.REMOTE_HANDLE);
        }
        keyProtectionTypes = CollectionUtil.unmodifiableSet(set);
    }

    @Override
    public Iterator<KeyProtectionType> iterator() {
        return keyProtectionTypes.iterator();
    }

    @Override
    public int size() {
        return keyProtectionTypes.size();
    }
}
