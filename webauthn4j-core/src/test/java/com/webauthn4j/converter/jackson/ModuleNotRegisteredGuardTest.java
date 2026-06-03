package com.webauthn4j.converter.jackson;

import com.webauthn4j.converter.util.ObjectConverter;
import tools.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.data.AuthenticatorTransport;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.StdSerializer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ModuleNotRegisteredGuardTest {

    // Guard annotations on data classes throw IllegalStateException when serialized/deserialized
    // without a WebAuthn module registered. This prevents silent incorrect serialization.
    // To use these types, either:
    //   1. Use ObjectConverter (recommended) - it registers WebAuthnJSONModule/WebAuthnCBORModule automatically
    //   2. Register WebAuthnJSONModule/WebAuthnCBORModule on your JsonMapper/CBORMapper manually
    //   3. Override the guard annotation via Jackson MixIn
    // Note: registering a custom serializer via Module alone is NOT sufficient because
    // Jackson resolves annotation-based serializers before module-registered ones.

    @Test
    void serialization_without_module_throws_exception() {
        JsonMapper plainMapper = JsonMapper.builder().build();
        assertThatThrownBy(() -> plainMapper.writeValueAsString(new TestDTO(AuthenticatorTransport.USB)))
                .hasRootCauseInstanceOf(IllegalStateException.class);
    }

    @Test
    void deserialization_without_module_throws_exception() {
        JsonMapper plainMapper = JsonMapper.builder().build();
        assertThatThrownBy(() -> plainMapper.readValue("{\"transport\":\"usb\"}", TestDTO.class))
                .hasRootCauseInstanceOf(IllegalStateException.class);
    }

    @Test
    void serialization_with_module_works() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonMapper jsonMapper = objectConverter.getJsonMapper();
        String json = jsonMapper.writeValueAsString(new TestDTO(AuthenticatorTransport.USB));
        assertThat(json).contains("\"usb\"");
    }

    @Test
    void deserialization_with_module_works() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonMapper jsonMapper = objectConverter.getJsonMapper();
        TestDTO dto = jsonMapper.readValue("{\"transport\":\"usb\"}", TestDTO.class);
        assertThat(dto.transport).isEqualTo(AuthenticatorTransport.USB);
    }

    @Test
    void custom_serializer_via_module_overrides_default() {
        ObjectConverter objectConverter = new ObjectConverter();
        SimpleModule customModule = new SimpleModule();
        customModule.addSerializer(new StdSerializer<AuthenticatorTransport>(AuthenticatorTransport.class) {
            @Override
            public void serialize(AuthenticatorTransport value, JsonGenerator gen, SerializationContext ctxt) {
                gen.writeString("custom:" + value.getValue());
            }
        });
        JsonMapper customMapper = objectConverter.getJsonMapper().rebuild().addModule(customModule).build();
        ObjectConverter customObjectConverter = new ObjectConverter(customMapper, objectConverter.getCborMapper());

        String json = customObjectConverter.getJsonMapper().writeValueAsString(new TestDTO(AuthenticatorTransport.USB));
        assertThat(json).isEqualTo("{\"transport\":\"custom:usb\"}");
    }

    @Test
    void custom_serializer_via_mixin_overrides_default() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonMapper mapper = objectConverter.getJsonMapper().rebuild()
                .addMixIn(AuthenticatorTransport.class, CustomSerializerMixin.class)
                .build();
        String json = mapper.writeValueAsString(new TestDTO(AuthenticatorTransport.USB));
        assertThat(json).isEqualTo("{\"transport\":\"mixin:usb\"}");
    }

    static class TestDTO {
        public AuthenticatorTransport transport;
        public TestDTO() {}
        public TestDTO(AuthenticatorTransport transport) { this.transport = transport; }
    }

    public static class MixinSerializer extends StdSerializer<AuthenticatorTransport> {
        public MixinSerializer() { super(AuthenticatorTransport.class); }
        @Override
        public void serialize(AuthenticatorTransport value, JsonGenerator gen, SerializationContext ctxt) {
            gen.writeString("mixin:" + value.getValue());
        }
    }

    @JsonSerialize(using = MixinSerializer.class)
    abstract static class CustomSerializerMixin {}
}
