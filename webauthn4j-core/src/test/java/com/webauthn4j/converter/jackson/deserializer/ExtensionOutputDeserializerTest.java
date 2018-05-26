package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.*;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class ExtensionOutputDeserializerTest {

    @Test
    public void deserialize_test_with_JSON_data() throws IOException {
        ObjectMapper objectMapper = ObjectMapperUtil.createJSONMapper(); // use JSON mapper to make test data readable

        Map<ExtensionIdentifier, ExtensionOutput> extensionOutputs =
                objectMapper.readValue(
                        "{ " +
                                "\"appid\": true, " +
                                "\"txAuthSimple\": \"authorization message\", " +
                                "\"txAuthGeneric\": { \"contentType\": \"image/png\", \"content\": null }, " +
                                "\"authnSel\": [], " +
                                "\"exts\": [\"exts\", \"authnSel\"], " +
                                "\"uvi\": null, " +
                                "\"loc\": { \"latitude\": 0, \"longitude\":0, \"accuracy\": 1 }, " +
                                "\"biometricPerfBounds\": { \"FAR\": 0, \"FRR\":0 } " +
                        "}",
                        new TypeReference<Map<ExtensionIdentifier, ExtensionOutput>>(){}
                );

        assertThat(extensionOutputs).containsKeys(FIDOAppIDExtensionOutput.ID, SupportedExtensionsExtensionOutput.ID);
        assertThat(extensionOutputs).containsValues(
                new FIDOAppIDExtensionOutput(true),
                new SimpleTransactionAuthorizationExtensionOutput("authorization message"),
                new GenericTransactionAuthorizationExtensionOutput(new GenericTransactionAuthorizationExtensionOutput.TxAuthnGenericArg("image/png", null)),
                new SupportedExtensionsExtensionOutput(Arrays.asList("exts", "authnSel"))
        );
    }
}
