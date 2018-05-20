package com.webauthn4j.validator;

import com.webauthn4j.client.TokenBinding;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.exception.TokenBindingException;

import java.util.Arrays;

public class TokenBindingValidator {

    public void validate(TokenBinding collectedClientDataTokenBinding, byte[] serverTokenBindingId) {
        if(collectedClientDataTokenBinding == null){
            // nop
        }
        else {
            byte[] clientDataTokenBindingId;
            if(collectedClientDataTokenBinding.getId() == null){
                clientDataTokenBindingId = null;
            }
            else {
                clientDataTokenBindingId = Base64UrlUtil.decode(collectedClientDataTokenBinding.getId());
            }
            switch (collectedClientDataTokenBinding.getStatus()){
                case NOT_SUPPORTED:
                    break;
                case SUPPORTED:
                    break;
                case PRESENT:
                    if(!Arrays.equals(clientDataTokenBindingId, serverTokenBindingId)){
                        throw new TokenBindingException("TokenBinding id does not match");
                    }
            }
        }
    }
}