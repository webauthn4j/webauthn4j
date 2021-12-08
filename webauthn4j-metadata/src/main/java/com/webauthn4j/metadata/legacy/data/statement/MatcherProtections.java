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

package com.webauthn4j.metadata.legacy.data.statement;

import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.util.CollectionUtil;

import java.util.AbstractSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

@Deprecated
public class MatcherProtections extends AbstractSet<MatcherProtectionType> {

    private final Set<MatcherProtectionType> matcherProtectionTypes;

    public MatcherProtections(int value) {
        Set<MatcherProtectionType> set = new HashSet<>();
        if ((value & MatcherProtectionType.SOFTWARE.getValue()) > 0) {
            set.add(MatcherProtectionType.SOFTWARE);
        }
        if ((value & MatcherProtectionType.TEE.getValue()) > 0) {
            set.add(MatcherProtectionType.TEE);
        }
        if ((value & MatcherProtectionType.ON_CHIP.getValue()) > 0) {
            set.add(MatcherProtectionType.ON_CHIP);
        }
        matcherProtectionTypes = CollectionUtil.unmodifiableSet(set);
    }

    @Override
    public Iterator<MatcherProtectionType> iterator() {
        return matcherProtectionTypes.iterator();
    }

    @Override
    public int size() {
        return matcherProtectionTypes.size();
    }
}
