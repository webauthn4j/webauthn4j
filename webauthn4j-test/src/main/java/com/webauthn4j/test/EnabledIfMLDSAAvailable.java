package com.webauthn4j.test;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(EnabledIfMLDSAAvailable.Condition.class)
public @interface EnabledIfMLDSAAvailable {

    class Condition implements ExecutionCondition {
        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
            try {
                KeyFactory.getInstance("ML-DSA-65");
                return ConditionEvaluationResult.enabled("ML-DSA is available");
            } catch (NoSuchAlgorithmException e) {
                return ConditionEvaluationResult.disabled("ML-DSA is not available on this runtime");
            }
        }
    }
}
