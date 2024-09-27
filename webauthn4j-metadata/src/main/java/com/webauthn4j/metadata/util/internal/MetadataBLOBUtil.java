package com.webauthn4j.metadata.util.internal;

import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.toc.StatusReport;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class MetadataBLOBUtil {

    private MetadataBLOBUtil(){}

    public static boolean checkMetadataBLOBPayloadEntry(@NotNull MetadataBLOBPayloadEntry metadataBLOBPayloadEntry, boolean notFidoCertifiedAllowed, boolean selfAssertionSubmittedAllowed) {
        List<StatusReport> statusReports = metadataBLOBPayloadEntry.getStatusReports();
        for (StatusReport report : statusReports) {
            switch (report.getStatus()) {
                //Info statuses
                case UPDATE_AVAILABLE:
                    // UPDATE_AVAILABLE itself doesn't mean security issue. If security related update is available,
                    // corresponding status report is expected to be added to the report list.
                    break;

                //Certification Related statuses
                case FIDO_CERTIFIED:
                case FIDO_CERTIFIED_L1:
                case FIDO_CERTIFIED_L1_PLUS:
                case FIDO_CERTIFIED_L2:
                case FIDO_CERTIFIED_L2_PLUS:
                case FIDO_CERTIFIED_L3:
                case FIDO_CERTIFIED_L3_PLUS:
                    break;
                case NOT_FIDO_CERTIFIED:
                    if (notFidoCertifiedAllowed) {
                        break;
                    }
                    else {
                        return false;
                    }
                case SELF_ASSERTION_SUBMITTED:
                    if (selfAssertionSubmittedAllowed) {
                        break;
                    }
                    else {
                        return false;
                    }

                    // Security Notification statuses
                case ATTESTATION_KEY_COMPROMISE:
                case USER_VERIFICATION_BYPASS:
                case USER_KEY_REMOTE_COMPROMISE:
                case USER_KEY_PHYSICAL_COMPROMISE:
                case REVOKED:
                default:
                    return false;
            }
        }
        return true;
    }
}
