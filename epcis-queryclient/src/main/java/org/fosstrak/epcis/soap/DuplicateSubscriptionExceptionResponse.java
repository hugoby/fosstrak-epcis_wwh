package org.fosstrak.epcis.soap;

import javax.xml.ws.WebFault;

/**
 * This class was generated by Apache CXF 2.2.9 Tue Jul 06 14:13:27 CEST 2010
 * Generated source version: 2.2.9
 */

@WebFault(name = "DuplicateSubscriptionException", targetNamespace = "urn:epcglobal:epcis-query:xsd:1")
public class DuplicateSubscriptionExceptionResponse extends Exception {
    public static final long serialVersionUID = 20100706141327L;

    private org.fosstrak.epcis.model.DuplicateSubscriptionException duplicateSubscriptionException;

    public DuplicateSubscriptionExceptionResponse() {
        super();
    }

    public DuplicateSubscriptionExceptionResponse(String message) {
        super(message);
    }

    public DuplicateSubscriptionExceptionResponse(String message, Throwable cause) {
        super(message, cause);
    }

    public DuplicateSubscriptionExceptionResponse(String message,
            org.fosstrak.epcis.model.DuplicateSubscriptionException duplicateSubscriptionException) {
        super(message);
        this.duplicateSubscriptionException = duplicateSubscriptionException;
    }

    public DuplicateSubscriptionExceptionResponse(String message,
            org.fosstrak.epcis.model.DuplicateSubscriptionException duplicateSubscriptionException, Throwable cause) {
        super(message, cause);
        this.duplicateSubscriptionException = duplicateSubscriptionException;
    }

    public org.fosstrak.epcis.model.DuplicateSubscriptionException getFaultInfo() {
        return this.duplicateSubscriptionException;
    }
}
