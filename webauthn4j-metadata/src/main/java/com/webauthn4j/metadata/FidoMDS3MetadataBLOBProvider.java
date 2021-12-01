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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;

public class FidoMDS3MetadataBLOBProvider extends CachingMetadataBLOBProvider{

    private static final String DEFAULT_BLOB_ENDPOINT = "https://mds.fidoalliance.org/";

    private final MetadataBLOBFactory metadataBLOBFactory;
    private final String blobEndpoint;
    private final HttpClient httpClient;

    public FidoMDS3MetadataBLOBProvider(ObjectConverter objectConverter, String blobEndpoint, HttpClient httpClient) {
        this.metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
        this.blobEndpoint = blobEndpoint;
        this.httpClient = httpClient;
    }

    public FidoMDS3MetadataBLOBProvider(ObjectConverter objectConverter, String blobEndpoint) {
        this(objectConverter, blobEndpoint, new SimpleHttpClient());
    }

    public FidoMDS3MetadataBLOBProvider(ObjectConverter objectConverter) {
        this(objectConverter, DEFAULT_BLOB_ENDPOINT);
    }

    @Override
    protected MetadataBLOB doProvide() {
        String responseBody = httpClient.fetch(blobEndpoint);
        return metadataBLOBFactory.parse(responseBody);
    }
}
