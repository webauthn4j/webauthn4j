module com.webauthn4j.test {
    requires transitive com.webauthn4j.core;
    requires transitive com.webauthn4j.appattest;
    requires transitive com.webauthn4j.metadata;
    requires transitive com.webauthn4j.core.async;

    requires org.slf4j;

    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;

    requires static org.jetbrains.annotations;

    exports com.webauthn4j.test;
    exports com.webauthn4j.test.authenticator;
    exports com.webauthn4j.test.authenticator.u2f;
    exports com.webauthn4j.test.authenticator.webauthn;
    exports com.webauthn4j.test.client;

}
