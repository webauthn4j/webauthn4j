module com.webauthn4j.spc.async {
    requires transitive com.webauthn4j.spc;
    requires transitive com.webauthn4j.core.async;

    requires org.slf4j;

    requires static org.jetbrains.annotations;

    exports com.webauthn4j.spc.async;
    exports com.webauthn4j.spc.async.verifier;
}
