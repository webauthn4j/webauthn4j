module com.webauthn4j.core.async {
    requires transitive com.webauthn4j.core;

    requires org.slf4j;
    requires com.fasterxml.jackson.core;

    requires static org.jetbrains.annotations;

    exports com.webauthn4j.async;
    exports com.webauthn4j.async.anchor;
    exports com.webauthn4j.async.verifier;
    exports com.webauthn4j.async.verifier.attestation.statement;
    exports com.webauthn4j.async.verifier.attestation.statement.androidkey;
    exports com.webauthn4j.async.verifier.attestation.statement.androidsafetynet;
    exports com.webauthn4j.async.verifier.attestation.statement.apple;
    exports com.webauthn4j.async.verifier.attestation.statement.none;
    exports com.webauthn4j.async.verifier.attestation.statement.packed;
    exports com.webauthn4j.async.verifier.attestation.statement.tpm;
    exports com.webauthn4j.async.verifier.attestation.statement.u2f;
    exports com.webauthn4j.async.verifier.attestation.trustworthiness.certpath;
    exports com.webauthn4j.async.verifier.attestation.trustworthiness.self;
    exports com.webauthn4j.async.util.internal to com.webauthn4j.metadata.async;
}
