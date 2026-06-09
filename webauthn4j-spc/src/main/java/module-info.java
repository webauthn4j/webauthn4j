module com.webauthn4j.spc {
    requires transitive com.webauthn4j.core;

    requires org.slf4j;

    requires static org.jetbrains.annotations;

    exports com.webauthn4j.spc;
    exports com.webauthn4j.spc.credential;
    exports com.webauthn4j.spc.converter.jackson;
    exports com.webauthn4j.spc.converter.jackson.deserializer.json;
    exports com.webauthn4j.spc.converter.jackson.serializer.json;
    exports com.webauthn4j.spc.data;
    exports com.webauthn4j.spc.data.client;
    exports com.webauthn4j.spc.data.extension.client;
    exports com.webauthn4j.spc.verifier;

    opens com.webauthn4j.spc.data;
    opens com.webauthn4j.spc.data.client;
    opens com.webauthn4j.spc.data.extension.client;
    opens com.webauthn4j.spc.converter.jackson.deserializer.json;
    opens com.webauthn4j.spc.converter.jackson.serializer.json;
}
