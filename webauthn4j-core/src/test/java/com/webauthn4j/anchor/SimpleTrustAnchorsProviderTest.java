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

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;

import java.security.cert.TrustAnchor;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@Deprecated
class SimpleTrustAnchorsProviderTest {

    @Test
    void provide_test() {
        TrustAnchor trustAnchor = mock(TrustAnchor.class);
        Set<TrustAnchor> trustAnchorSet = new HashSet<>();
        trustAnchorSet.add(trustAnchor);
        SimpleTrustAnchorsProvider target = new SimpleTrustAnchorsProvider(trustAnchorSet);

        Map<AAGUID, Set<TrustAnchor>> trustAnchors = target.provide();
        assertThat(trustAnchors.keySet()).containsExactly(AAGUID.NULL);
        assertThat(trustAnchors.get(AAGUID.NULL)).hasSameElementsAs(trustAnchorSet);
    }

}