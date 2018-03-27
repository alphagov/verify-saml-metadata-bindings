package uk.gov.ida.saml.metadata;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;

import javax.annotation.Nullable;

public class SingleIdpEntityDescriptorFilter implements MetadataFilter {
    @Nullable
    @Override
    public XMLObject filter(@Nullable XMLObject metadata) throws FilterException {
        return metadata;
    }
}
