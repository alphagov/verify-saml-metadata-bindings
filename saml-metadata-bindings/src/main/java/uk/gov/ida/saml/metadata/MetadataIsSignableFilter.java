package uk.gov.ida.saml.metadata;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.xmlsec.signature.SignableXMLObject;

import javax.annotation.Nullable;

public class MetadataIsSignableFilter implements MetadataFilter {
    @Nullable
    @Override
    public XMLObject filter(@Nullable XMLObject metadata) throws FilterException {
        if (metadata == null) return null;
        if (!(metadata instanceof SignableXMLObject)) throw new FilterException("Metadata should be signed.");
        return metadata;
    }
}
