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

import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.util.UUIDUtil;
import org.junit.Test;

import java.security.cert.TrustAnchor;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class TrustAnchorResolverImplTest {

    @Test
    public void test(){
        TrustAnchorResolverImpl target = new TrustAnchorResolverImpl(new SampleTrustAnchorProvider());

        Set<TrustAnchor> trustAnchorsA = target.resolve(AAGUID.ZERO);
        Set<TrustAnchor> trustAnchorsB = target.resolve(AAGUID.ZERO);
        assertThat(trustAnchorsA).isEqualTo(trustAnchorsB);
    }

}
