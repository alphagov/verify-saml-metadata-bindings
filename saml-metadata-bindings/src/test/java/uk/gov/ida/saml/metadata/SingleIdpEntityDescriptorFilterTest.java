package uk.gov.ida.saml.metadata;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

public class SingleIdpEntityDescriptorFilterTest {

    private MetadataFilter testFilter;

    @Before
    public void setUp() throws Exception {
        testFilter = new SingleIdpEntityDescriptorFilter();
    }

    @Test
    public void shouldReturnNullIfMetadataIsNull() throws FilterException {
        XMLObject filterResult = testFilter.filter(null);
        assertThat(filterResult).isNull();
    }

    @Test
    public void shouldReturnMetadataIfHasSingleIdpDescriptor() throws FilterException {
        XMLObject testMetadata = mock(XMLObject.class);
        XMLObject filterResult = testFilter.filter(testMetadata);
        assertThat(filterResult).isEqualTo(testMetadata);
    }

    @Test
    public void shouldThrowExceptionIfMetadataHasMultipleIdpDescriptors() {
        XMLObject testMetadata = mock(XMLObject.class);
        assertThatExceptionOfType(FilterException.class)
                .isThrownBy(() -> testFilter.filter(testMetadata));
    }
}
