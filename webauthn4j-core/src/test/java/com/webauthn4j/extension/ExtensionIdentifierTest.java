package com.webauthn4j.extension;

import com.webauthn4j.extension.authneticator.GenericTransactionAuthorizationAuthenticatorExtensionOutput;
import com.webauthn4j.extension.authneticator.SimpleTransactionAuthorizationAuthenticatorExtensionOutput;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ExtensionIdentifierTest {

    @Test
    public void equals_hashCode_test(){
        ExtensionIdentifier txAuthGenericA = GenericTransactionAuthorizationAuthenticatorExtensionOutput.ID;
        ExtensionIdentifier txAuthGenericB = GenericTransactionAuthorizationAuthenticatorExtensionOutput.ID;
        ExtensionIdentifier txAuthSimple = SimpleTransactionAuthorizationAuthenticatorExtensionOutput.ID;

        assertThat(txAuthGenericA).isEqualTo(txAuthGenericB);
        assertThat(txAuthGenericA).hasSameHashCodeAs(txAuthGenericB);

        assertThat(txAuthGenericA).isNotEqualTo(txAuthSimple);
        assertThat(txAuthGenericA.hashCode()).isNotEqualTo(txAuthSimple.hashCode());
    }

}
