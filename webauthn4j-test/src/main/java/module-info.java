module com.webauthn4j.test {
    requires com.webauthn4j.util;
    requires com.webauthn4j.core;
    requires com.webauthn4j.core.async;
    requires com.webauthn4j.appattest;

    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.cbor;

    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;

    exports com.webauthn4j.test;
    exports com.webauthn4j.test.authenticator;
    exports com.webauthn4j.test.authenticator.u2f;
    exports com.webauthn4j.test.authenticator.webauthn;
    exports com.webauthn4j.test.client;

}
