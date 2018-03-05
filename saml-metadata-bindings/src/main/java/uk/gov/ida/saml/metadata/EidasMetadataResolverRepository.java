package uk.gov.ida.saml.metadata;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;
import io.dropwizard.setup.Environment;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.trustanchor.CountryTrustAnchor;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;

import javax.inject.Inject;
import javax.ws.rs.core.UriBuilder;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.stream.Collectors;

public class EidasMetadataResolverRepository {

    private final Logger log = LoggerFactory.getLogger(EidasMetadataResolverRepository.class);
    private final EidasTrustAnchorResolver trustAnchorResolver;
    private final DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;
    private HashMap<String, MetadataResolver> metadataResolvers = new HashMap<>();
    private List<JWK> trustAnchors = new ArrayList<>();
    private final Environment environment;
    private final EidasMetadataConfiguration eidasMetadataConfiguration;
    private final Timer timer;
    private long delayBeforeNextRefresh;

    @Inject
    public EidasMetadataResolverRepository(EidasTrustAnchorResolver trustAnchorResolver, Environment environment, EidasMetadataConfiguration eidasMetadataConfiguration, DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory, Timer timer) {
        this.trustAnchorResolver = trustAnchorResolver;
        this.environment = environment;
        this.eidasMetadataConfiguration = eidasMetadataConfiguration;
        this.dropwizardMetadataResolverFactory = dropwizardMetadataResolverFactory;
        this.timer = timer;

        refresh();
    }

    public MetadataResolver getMetadataResolver(String entityId) {
        return metadataResolvers.get(entityId);
    }

    public HashMap<String, MetadataResolver> getMetadataResolvers(){
        return metadataResolvers;
    }

    public List<String> getTrustAnchorsEntityIds() {
        return trustAnchors.stream().map(JWK::getKeyID).collect(Collectors.toList());
    }

    private void refresh() {
        delayBeforeNextRefresh =  eidasMetadataConfiguration.getTrustAnchorMaxRefreshDelay();
        try {
            trustAnchors = trustAnchorResolver.getTrustAnchors();
            removeMetadataResolvers();
            registerMetadataResolvers(trustAnchors);
        } catch (Exception e) {
            log.error("Error fetching trust anchor or validating it", e);
            setShortRefreshDelay();
        } finally {
            timer.schedule(new RefreshTimerTask(), delayBeforeNextRefresh);
        }
    }

    private void registerMetadataResolvers(List<JWK> trustAnchors) {
        for(JWK trustAnchor : trustAnchors) {
            try {
                X509Certificate certificate = X509CertUtils.parse(Base64.decode(String.valueOf(trustAnchor.getX509CertChain().get(0))));
                certificate.checkValidity();

                addMetadataResolver(trustAnchor);
                Collection<String> errors = CountryTrustAnchor.findErrors(trustAnchor);
                if (!errors.isEmpty()) {
                    throw new Error(String.format("Managed to generate an invalid anchor: %s", String.join(", ", errors)));
                }

                Date metadataSigningCertExpiryDate = certificate.getNotAfter();
                Date nextRunTime = DateTime.now().plus(delayBeforeNextRefresh).toDate();
                if (metadataSigningCertExpiryDate.before(nextRunTime)) {
                    setShortRefreshDelay();
                }
            } catch (Exception e) {
                log.error("Error creating MetadataResolver for " + trustAnchor.getKeyID(), e);
            }
        }
    }

    private void addMetadataResolver(JWK trustAnchor) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        MetadataResolver metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(environment, createMetadataResolverConfiguration(trustAnchor));
        metadataResolvers.put(trustAnchor.getKeyID(), metadataResolver);
    }

    private MetadataResolverConfiguration createMetadataResolverConfiguration(JWK trustAnchor)
            throws UnsupportedEncodingException, CertificateException, KeyStoreException {

        URI metadataUri = UriBuilder.fromUri(eidasMetadataConfiguration.getMetadataBaseUri())
                .path(URLEncoder.encode(trustAnchor.getKeyID(), "UTF-8"))
                .build();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> trustedCertChain = trustAnchor.getX509CertChain()
                .stream()
                .map(base64 -> base64.decode())
                .map(certBytes -> new ByteArrayInputStream(certBytes))
                .map(certStream -> {
                    try { //Java streams don't allow throwing checked exceptions
                        return (X509Certificate) certificateFactory.generateCertificate(certStream);
                    } catch (CertificateException e) {
                        throw new RuntimeException("Certificate in Trust Anchor x5c is not a valid x509", e);
                    }
                })
                .collect(Collectors.toList());

        return new TrustStoreBackedMetadataConfiguration(
                metadataUri,
                eidasMetadataConfiguration.getMinRefreshDelay(),
                eidasMetadataConfiguration.getMaxRefreshDelay(),
                null,
                eidasMetadataConfiguration.getJerseyClientConfiguration(),
                getClientName(trustAnchor.getKeyID()),
                null,
                new DynamicTrustStoreConfiguration(buildKeyStoreFromCertificate(trustedCertChain))
                );
    }

    private void removeMetadataResolvers() {
        for(String entityId : metadataResolvers.keySet()) {
            MetadataResolver metadataResolver = metadataResolvers.get(entityId);
            if (metadataResolver instanceof AbstractReloadingMetadataResolver){
                ((AbstractReloadingMetadataResolver) metadataResolver).destroy();
            }
            environment.metrics().remove(getClientName(entityId));
            metadataResolvers.remove(entityId);
        }
    }

    private KeyStore buildKeyStoreFromCertificate(List<X509Certificate> certificates) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            for(X509Certificate certificate : certificates) {
                keyStore.setCertificateEntry("certificate-" + certificates.indexOf(certificate), certificate);
            }
            return keyStore;
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String getClientName(String entityId) {
        return String.format("%s - %s", eidasMetadataConfiguration.getJerseyClientName(), entityId);
    }

    private class RefreshTimerTask extends TimerTask {
        @Override
        public void run() {
            refresh();
        }
    }

    private void setShortRefreshDelay() {
        delayBeforeNextRefresh = eidasMetadataConfiguration.getTrustAnchorMinRefreshDelay();
    }

    public boolean hasMetadataResolverForEntity(String entityId){
        return metadataResolvers.containsKey(entityId);
    }
}
