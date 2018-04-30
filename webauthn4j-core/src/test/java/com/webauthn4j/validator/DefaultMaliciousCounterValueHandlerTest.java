package com.webauthn4j.validator;

import com.webauthn4j.validator.exception.MaliciousCounterValueException;
import org.junit.Test;

public class DefaultMaliciousCounterValueHandlerTest {

    private DefaultMaliciousCounterValueHandler target = new DefaultMaliciousCounterValueHandler();

    @Test(expected = MaliciousCounterValueException.class)
    public void maliciousCounterValueDetected_test(){
        target.maliciousCounterValueDetected(null, null);
    }


}
