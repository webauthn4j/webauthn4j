module com.webauthn4j.metadata.async {
    requires java.net.http;

    requires com.webauthn4j.util;
    requires com.webauthn4j.core;
    requires com.webauthn4j.core.async;
    requires com.webauthn4j.metadata;

    requires org.jetbrains.annotations;

    exports com.webauthn4j.async.metadata;
    exports com.webauthn4j.async.metadata.anchor;
}
