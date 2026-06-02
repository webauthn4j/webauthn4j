package com.webauthn4j.metadata.converter.jackson;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.MetadataCodecFallbackRegistrar;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import com.webauthn4j.metadata.data.uaf.AAID;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ModuleNotRegisteredGuardMetadataTest {

    private static String loadResourceAsString(String classPath) {
        try (InputStream inputStream = ModuleNotRegisteredGuardMetadataTest.class.getClassLoader().getResourceAsStream(classPath)) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // --- Guard behavior tests ---

    @Test
    void aaid_serialization_without_module_throws_exception() {
        JsonMapper plainMapper = JsonMapper.builder().build();
        assertThatThrownBy(() -> plainMapper.writeValueAsString(new AIDDTO(new AAID("1234#5678"))))
                .hasRootCauseInstanceOf(IllegalStateException.class);
    }

    @Test
    void aaid_deserialization_without_module_throws_exception() {
        JsonMapper plainMapper = JsonMapper.builder().build();
        assertThatThrownBy(() -> plainMapper.readValue("{\"aaid\":\"1234#5678\"}", AIDDTO.class))
                .hasRootCauseInstanceOf(IllegalStateException.class);
    }

    @Test
    void authenticatorStatus_serialization_without_module_throws_exception() {
        JsonMapper plainMapper = JsonMapper.builder().build();
        assertThatThrownBy(() -> plainMapper.writeValueAsString(new StatusDTO(AuthenticatorStatus.FIDO_CERTIFIED)))
                .hasRootCauseInstanceOf(IllegalStateException.class);
    }

    // --- Explicit module registration tests ---

    @Test
    void aaid_serialization_with_explicit_module_works() {
        ObjectConverter objectConverter = new ObjectConverter().rebuildWithJSONModule(new WebAuthnMetadataJSONModule());
        String json = objectConverter.getJsonMapper().writeValueAsString(new AIDDTO(new AAID("1234#5678")));
        assertThat(json).contains("\"1234#5678\"");
    }

    @Test
    void authenticatorStatus_serialization_with_explicit_module_works() {
        ObjectConverter objectConverter = new ObjectConverter().rebuildWithJSONModule(new WebAuthnMetadataJSONModule());
        String json = objectConverter.getJsonMapper().writeValueAsString(new StatusDTO(AuthenticatorStatus.FIDO_CERTIFIED));
        assertThat(json).contains("\"FIDO_CERTIFIED\"");
    }

    // --- Auto-registration via MetadataBLOBFactory tests ---

    @Test
    void metadataBLOBFactory_auto_registers_fallback_and_logs_warn_when_module_not_registered() {
        Logger factoryLogger = (Logger) LoggerFactory.getLogger(MetadataCodecFallbackRegistrar.class);
        ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
        listAppender.start();
        factoryLogger.addAppender(listAppender);
        try {
            ObjectConverter objectConverter = new ObjectConverter();
            MetadataBLOBFactory factory = new MetadataBLOBFactory(objectConverter);
            String blobJwt = loadResourceAsString("integration/component/blob.jwt");
            assertThat(factory.parse(blobJwt)).isNotNull();

            assertThat(listAppender.list).anyMatch(event ->
                    event.getLevel() == Level.WARN
                    && event.getFormattedMessage().contains("WebAuthnMetadataJSONModule is not registered"));
        } finally {
            factoryLogger.detachAppender(listAppender);
        }
    }

    // --- Custom serializer via MixIn override tests ---

    @Test
    void custom_serializer_via_mixin_overrides_default_for_metadata_type() {
        ObjectConverter objectConverter = new ObjectConverter().rebuildWithJSONModule(new WebAuthnMetadataJSONModule());
        JsonMapper mapper = objectConverter.getJsonMapper().rebuild()
                .addMixIn(AuthenticatorStatus.class, CustomStatusSerializerMixin.class)
                .build();
        String json = mapper.writeValueAsString(new StatusDTO(AuthenticatorStatus.FIDO_CERTIFIED));
        assertThat(json).isEqualTo("{\"status\":\"custom:FIDO_CERTIFIED\"}");
    }

    // --- Custom serializer via module tests ---

    @Test
    void custom_serializer_via_module_overrides_default_when_explicit_module_registered() {
        ObjectConverter objectConverter = new ObjectConverter().rebuildWithJSONModule(new WebAuthnMetadataJSONModule());
        SimpleModule customModule = new SimpleModule();
        customModule.addSerializer(new CustomAuthenticatorStatusSerializer());
        JsonMapper customMapper = objectConverter.getJsonMapper().rebuild().addModule(customModule).build();
        ObjectConverter customObjectConverter = new ObjectConverter(customMapper, objectConverter.getCborMapper());

        String json = customObjectConverter.getJsonMapper().writeValueAsString(new StatusDTO(AuthenticatorStatus.FIDO_CERTIFIED));
        assertThat(json).isEqualTo("{\"status\":\"custom:FIDO_CERTIFIED\"}");
    }

    // --- DTOs ---

    static class AIDDTO {
        public AAID aaid;
        public AIDDTO() {}
        public AIDDTO(AAID aaid) { this.aaid = aaid; }
    }

    static class StatusDTO {
        public AuthenticatorStatus status;
        public StatusDTO() {}
        public StatusDTO(AuthenticatorStatus status) { this.status = status; }
    }

    // --- Custom serializer and MixIn ---

    public static class CustomAuthenticatorStatusSerializer extends StdSerializer<AuthenticatorStatus> {
        public CustomAuthenticatorStatusSerializer() { super(AuthenticatorStatus.class); }
        @Override
        public void serialize(AuthenticatorStatus value, JsonGenerator gen, SerializationContext ctxt) {
            gen.writeString("custom:" + value.getValue());
        }
    }

    @JsonSerialize(using = CustomAuthenticatorStatusSerializer.class)
    abstract static class CustomStatusSerializerMixin {}
}
