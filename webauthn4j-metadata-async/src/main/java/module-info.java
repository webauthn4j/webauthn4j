module com.webauthn4j.metadata.async {
    requires java.net.http;

    requires transitive com.webauthn4j.core.async;
    requires transitive com.webauthn4j.metadata;

    requires org.slf4j;

    requires static org.jetbrains.annotations;

    exports com.webauthn4j.async.metadata;
    exports com.webauthn4j.async.metadata.anchor;
}
