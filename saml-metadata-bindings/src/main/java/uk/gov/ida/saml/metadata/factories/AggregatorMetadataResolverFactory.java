package uk.gov.ida.saml.metadata.factories;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.filter.FilterException;
import org.opensaml.saml.metadata.resolver.filter.MetadataFilter;
import org.opensaml.saml.metadata.resolver.filter.impl.SchemaValidationFilter;
import org.opensaml.saml.metadata.resolver.filter.impl.SignatureValidationFilter;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.MetadataIsSignableFilter;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;

import javax.annotation.Nullable;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import java.net.URI;
import java.security.KeyStore;
import java.util.List;

import static java.util.Arrays.asList;

public class AggregatorMetadataResolverFactory {

    private final MetadataResolverFactory metadataResolverFactory = new MetadataResolverFactory();
    private final ExpiredCertificateMetadataFilter expiredCertificateMetadataFilter = new ExpiredCertificateMetadataFilter();

    public MetadataResolver createMetadataResolver(MetadataResolverConfiguration metadataConfiguration) {
        URI uri = metadataConfiguration.getUri();
        Long minRefreshDelay = metadataConfiguration.getMinRefreshDelay();
        Long maxRefreshDelay = metadataConfiguration.getMaxRefreshDelay();
        Client client = ClientBuilder.newClient();

        return metadataResolverFactory.create(
            client,
            uri,
            getMetadataFilters(metadataConfiguration),
            minRefreshDelay,
            maxRefreshDelay
        );
    }

    private List<MetadataFilter> getMetadataFilters(MetadataResolverConfiguration metadataConfiguration) {
        MetadataFilter signatureMatchesTrustAnchorFilter = basicAssMetadataFilter();
        MetadataFilter singleIdpEntityInDescriptorFilter = basicAssMetadataFilter();
        MetadataFilter descriptorEntityIdMatchesUrlAndKidFilter = basicAssMetadataFilter();
        MetadataFilter titleDescriptorContainsSigningCertificateFilter = basicAssMetadataFilter();
        MetadataFilter descriptorIncludesSSOLocationFilter = basicAssMetadataFilter();
        MetadataFilter descriptorIncludesExpectedAttributesFilter = basicAssMetadataFilter();

        return asList(
                new MetadataIsSignableFilter(),
                schemaFilter(),
                signatureMatchesTrustAnchorFilter,
                singleIdpEntityInDescriptorFilter,
                descriptorEntityIdMatchesUrlAndKidFilter,
                titleDescriptorContainsSigningCertificateFilter,
                descriptorIncludesSSOLocationFilter,
                descriptorIncludesExpectedAttributesFilter,
                signatureValidationFilter(metadataConfiguration),
                expiredCertificateMetadataFilter
        );
    }

    //TODO Remove all uses of this for the love of god
    private MetadataFilter basicAssMetadataFilter() {
        return new MetadataFilter() {
            @Nullable
            @Override
            public XMLObject filter(@Nullable XMLObject metadata) throws FilterException {
                throw new FilterException();
            }
        };
    }

    private SignatureValidationFilter signatureValidationFilter(MetadataResolverConfiguration metadataConfiguration) {
        KeyStore metadataTrustStore = metadataConfiguration.getTrustStore();
        PKIXSignatureValidationFilterProvider pkixSignatureValidationFilterProvider = new PKIXSignatureValidationFilterProvider(metadataTrustStore);
        return pkixSignatureValidationFilterProvider.get();
    }

    private SchemaValidationFilter schemaFilter() {
        //TODO Check this version
        SAMLSchemaBuilder builder = new SAMLSchemaBuilder(SAMLSchemaBuilder.SAML1Version.SAML_11);
        return new SchemaValidationFilter(builder);
    }
}
