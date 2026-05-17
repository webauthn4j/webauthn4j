package com.webauthn4j.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.converter.jackson.deserializer.json.ExtensionClientOutputDeserializer;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that external modules can register custom WebAuthn extensions
 * via Jackson Module and retrieve them through getExtension(Class).
 */
class ExternalExtensionRegistrationTest {

    // -- Example extension data class (simulates an external module's extension) --

    static class ExampleExtensionClientOutput implements AuthenticationExtensionClientOutput {

        public static final String KEY = "exampleExtension";

        private final String exampleValue;
        private final Boolean exampleFlag;

        @JsonCreator
        ExampleExtensionClientOutput(
                @JsonProperty("exampleValue") String exampleValue,
                @JsonProperty("exampleFlag") Boolean exampleFlag) {
            this.exampleValue = exampleValue;
            this.exampleFlag = exampleFlag;
        }

        @Override
        public @NotNull String getIdentifier() {
            return KEY;
        }

        @Override
        public @Nullable Object getValue(@NotNull String key) {
            switch (key) {
                case "exampleValue":
                    return exampleValue;
                case "exampleFlag":
                    return exampleFlag;
                default:
                    throw new IllegalArgumentException(String.format("%s is not a valid key.", key));
            }
        }

        public String getExampleValue() {
            return exampleValue;
        }

        public Boolean getExampleFlag() {
            return exampleFlag;
        }

        @Override
        public void validate() {
            if (exampleValue == null) {
                throw new ConstraintViolationException("exampleValue must not be null");
            }
        }
    }

    // -- Example deserializer --

    static class ExampleExtensionClientOutputDeserializer
            extends ExtensionClientOutputDeserializer<ExampleExtensionClientOutput> {

        ExampleExtensionClientOutputDeserializer() {
            super(ExampleExtensionClientOutput.class);
        }

        @Override
        public @NotNull Set<String> getKeys() {
            return Set.of("exampleExtension");
        }

        @Override
        public ExampleExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
            ObjectNode node = (ObjectNode) p.readValueAsTree();
            JsonNode value = node.get("exampleExtension");
            if (value == null || value.isNull()) return null;
            // Must not call readTreeAsValue with the same class as this deserializer handles,
            // as it would recursively invoke this deserializer. Construct directly instead.
            String exampleValue = value.has("exampleValue") ? value.get("exampleValue").asText() : null;
            Boolean exampleFlag = value.has("exampleFlag") ? value.get("exampleFlag").asBoolean() : null;
            return new ExampleExtensionClientOutput(exampleValue, exampleFlag);
        }
    }

    // -- Example Jackson Module --

    static class ExampleExtensionModule extends SimpleModule {
        ExampleExtensionModule() {
            super("ExampleExtensionModule");
            this.addDeserializer(ExampleExtensionClientOutput.class,
                    new ExampleExtensionClientOutputDeserializer());
        }
    }

    @Test
    void getExtension_should_return_external_extension() {
        // Register external module in ObjectConverter
        JsonMapper jsonMapper = JsonMapper.builder()
                .addModule(new ExampleExtensionModule())
                .build();
        ObjectConverter objectConverter = new ObjectConverter(jsonMapper, new tools.jackson.dataformat.cbor.CBORMapper());

        // Deserialize JSON containing the external extension
        String json = "{\"appid\": true, \"exampleExtension\": {\"exampleValue\": \"hello\", \"exampleFlag\": true}}";
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> outputs =
                objectConverter.getJsonMapper().readValue(json,
                        new TypeReference<AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput>>() {});

        // Known extension works as before
        assertThat(outputs.getAppid()).isTrue();

        // External extension is retrievable via getExtension(Class)
        // Note: ExampleExtensionClientOutput implements AuthenticationExtensionClientOutput,
        // so it satisfies the type constraint <E extends T>
        ExampleExtensionClientOutput example = outputs.getExtension(ExampleExtensionClientOutput.class);
        assertThat(example).isNotNull();
        assertThat(example.getExampleValue()).isEqualTo("hello");
        assertThat(example.getExampleFlag()).isTrue();
        assertThat(example.getIdentifier()).isEqualTo("exampleExtension");

        // External extension key is reported as unknown (not in KNOWN_KEYS)
        assertThat(outputs.getUnknownKeys()).contains("exampleExtension");

        // getExtensions() does not include external extensions (only KNOWN_TYPES)
        assertThat(outputs.getExtensions()).doesNotContainKey(ExampleExtensionClientOutput.class);
    }

    @Test
    void getExtension_should_return_null_when_external_extension_absent() {
        JsonMapper jsonMapper = JsonMapper.builder()
                .addModule(new ExampleExtensionModule())
                .build();
        ObjectConverter objectConverter = new ObjectConverter(jsonMapper, new tools.jackson.dataformat.cbor.CBORMapper());

        String json = "{\"appid\": true}";
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> outputs =
                objectConverter.getJsonMapper().readValue(json,
                        new TypeReference<AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput>>() {});

        ExampleExtensionClientOutput example = outputs.getExtension(ExampleExtensionClientOutput.class);
        assertThat(example).isNull();
    }

    @Test
    void builder_with_external_extension_via_set() {
        JsonMapper jsonMapper = JsonMapper.builder()
                .addModule(new ExampleExtensionModule())
                .build();
        ObjectConverter objectConverter = new ObjectConverter(jsonMapper, new tools.jackson.dataformat.cbor.CBORMapper());

        // Build with external extension using set(key, value)
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder =
                new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder.setObjectConverter(objectConverter);
        builder.setAppid(true);
        builder.set("exampleExtension", new ExampleExtensionClientOutput("world", false));
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> outputs = builder.build();

        // Verify round-trip through Builder → getExtension
        assertThat(outputs.getAppid()).isTrue();
        ExampleExtensionClientOutput example = outputs.getExtension(ExampleExtensionClientOutput.class);
        assertThat(example).isNotNull();
        assertThat(example.getExampleValue()).isEqualTo("world");
        assertThat(example.getExampleFlag()).isFalse();
    }
}
