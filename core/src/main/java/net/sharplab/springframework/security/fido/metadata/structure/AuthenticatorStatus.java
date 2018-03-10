package net.sharplab.springframework.security.fido.metadata.structure;

/**
 * Created by ynojima on 2017/09/08.
 */
public enum AuthenticatorStatus {
    FIDO_CERTIFIED,
    NOT_FIDO_CERTIFIED,
    USER_VERIFICATION_BYPASS,
    ATTESTATION_KEY_COMPROMISE,
    USER_KEY_REMOTE_COMPROMISE,
    USER_KEY_PHYSICAL_COMPROMISE,
    UPDATE_AVAILABLE,
    REVOKED
}
