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

package com.webauthn4j.metadata;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataItem;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FidoMdsTrustAnchorsProviderAdaptorTest {

    @SuppressWarnings("unchecked")
    @Test
    void provide_test() {
        MetadataItemsProvider<MetadataItem> metadataItemsProvider = mock(MetadataItemsProvider.class);
        AAGUID aaguid = new AAGUID("49e25c43-a6d1-49f0-bcfa-23e23a7c0e52");
        when(metadataItemsProvider.provide()).thenReturn(Collections.singletonMap(aaguid, Collections.singleton(TestDataUtil.createFidoMdsMetadataItem())));
        FidoMdsTrustAnchorsProviderAdaptor fidoMdsTrustAnchorsProviderAdaptor = new FidoMdsTrustAnchorsProviderAdaptor(metadataItemsProvider);
        Map<AAGUID, Set<TrustAnchor>> result = fidoMdsTrustAnchorsProviderAdaptor.provide();
        assertThat(result.get(aaguid).stream().map(TrustAnchor::getTrustedCert)).contains(TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate());
    }

}