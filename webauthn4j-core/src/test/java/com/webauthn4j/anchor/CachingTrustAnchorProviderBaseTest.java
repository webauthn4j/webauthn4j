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

package com.webauthn4j.anchor;

import org.junit.Test;

import java.security.cert.TrustAnchor;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class CachingTrustAnchorProviderBaseTest {

    @Test
    public void test(){
        CachingTrustAnchorProviderBaseImpl target = new CachingTrustAnchorProviderBaseImpl();

        Set<TrustAnchor> trustAnchorsA = target.provide();
        Set<TrustAnchor> trustAnchorsB = target.provide();
        assertThat(trustAnchorsA).isEqualTo(trustAnchorsB);
    }

    class CachingTrustAnchorProviderBaseImpl extends CachingTrustAnchorProviderBase {

        @Override
        protected Set<TrustAnchor> loadTrustAnchors() {
            return new HashSet<>();
        }
    }
}
