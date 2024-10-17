module com.webauthn4j.metadata {
    requires com.webauthn4j.util;
    requires com.webauthn4j.core;

    requires org.slf4j;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.cbor;
    requires com.fasterxml.jackson.datatype.jsr310;

    requires static org.jetbrains.annotations;

    exports com.webauthn4j.metadata;
    exports com.webauthn4j.metadata.anchor;
    exports com.webauthn4j.metadata.converter.jackson;
    exports com.webauthn4j.metadata.converter.jackson.deserializer;
    exports com.webauthn4j.metadata.data;
    exports com.webauthn4j.metadata.data.statement;
    exports com.webauthn4j.metadata.data.toc;
    exports com.webauthn4j.metadata.data.uaf;
    exports com.webauthn4j.metadata.exception;
    exports com.webauthn4j.metadata.util.internal to com.webauthn4j.metadata.async;
}
