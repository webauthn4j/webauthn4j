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

package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.util.CollectionUtil;

import java.util.AbstractSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class MatcherProtections extends AbstractSet<MatcherProtection> {

    private Set<MatcherProtection> matcherProtections;

    public MatcherProtections(int value) {
        Set<MatcherProtection> set = new HashSet<>();
        if ((value & MatcherProtection.SOFTWARE.getValue()) > 0) {
            set.add(MatcherProtection.SOFTWARE);
        }
        if ((value & MatcherProtection.TEE.getValue()) > 0) {
            set.add(MatcherProtection.TEE);
        }
        if ((value & MatcherProtection.ON_CHIP.getValue()) > 0) {
            set.add(MatcherProtection.ON_CHIP);
        }
        matcherProtections = CollectionUtil.unmodifiableSet(set);
    }

    @Override
    public Iterator<MatcherProtection> iterator() {
        return matcherProtections.iterator();
    }

    @Override
    public int size() {
        return matcherProtections.size();
    }
}
