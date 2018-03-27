package uk.gov.ida.saml.metadata;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.xmlsec.signature.SignableXMLObject;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

public class MetadataIsSignableFilterTest {

    private MetadataIsSignableFilter testFilter;

    @Before
    public void setUp() throws Exception {
        testFilter = new MetadataIsSignableFilter();
    }

    @Test
    public void shouldPassIfMetadataIsNull() throws FilterException {
        testFilter.filter(null);
    }

    @Test
    public void shouldReturnNullIfPassedNull() throws FilterException {
        assertThat(testFilter.filter(null)).isNull();
    }

    @Test
    public void shouldPassIfMetadataIsSignable() throws FilterException {
        testFilter.filter(mock(SignableXMLObject.class));
    }

    @Test
    public void shouldReturnMetadataObjectIntactIfIsSignable() throws FilterException {
        SignableXMLObject mockXmlObject = mock(SignableXMLObject.class);
        assertThat(mockXmlObject).isEqualTo(testFilter.filter(mockXmlObject));
    }

    @Test
    public void shouldThrowExceptionIfMetadataIsNotSignable() {
        assertThatExceptionOfType(FilterException.class)
                .isThrownBy(() -> testFilter.filter(mock(XMLObject.class)));
    }
}
