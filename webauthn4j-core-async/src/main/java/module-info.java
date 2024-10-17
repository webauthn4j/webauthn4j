module com.webauthn4j.core.async {
    requires com.webauthn4j.util;
    requires com.webauthn4j.core;

    requires org.slf4j;
    requires com.fasterxml.jackson.core;

    requires static org.jetbrains.annotations;

    exports com.webauthn4j.async;
    exports com.webauthn4j.async.anchor;
    exports com.webauthn4j.async.verifier;
    exports com.webauthn4j.async.util.internal to com.webauthn4j.metadata.async;
}
