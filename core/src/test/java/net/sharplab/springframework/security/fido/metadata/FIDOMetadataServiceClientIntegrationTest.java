package net.sharplab.springframework.security.fido.metadata;

import net.sharplab.springframework.security.fido.metadata.structure.MetadataStatement;
import net.sharplab.springframework.security.fido.metadata.structure.MetadataTOCPayload;
import net.sharplab.springframework.security.fido.metadata.structure.MetadataTOCPayloadEntry;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.io.Console;
import java.net.URI;

/**
 * Test for FIDOMetadataServiceClient
 */

public class FIDOMetadataServiceClientIntegrationTest {

    private FIDOMetadataServiceClient target;

    @Before
    public void setup(){
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory();
        RestTemplate restTemplate = new RestTemplate(httpComponentsClientHttpRequestFactory);
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        target = new FIDOMetadataServiceClient(restTemplate, resourceLoader);
    }

    @Test
    public void retrieveMetadataTOC_test(){
        MetadataTOCPayload metadataTOC = target.retrieveMetadataTOC();

    }

    @Test
    public void retrieveMetadataStatement_test() throws Exception{
        URI uri = new URI("https://mds.fidoalliance.org/metadata/4e4e%23400a");
        MetadataStatement metadataStatement = target.retrieveMetadataStatement(uri);

    }
}
