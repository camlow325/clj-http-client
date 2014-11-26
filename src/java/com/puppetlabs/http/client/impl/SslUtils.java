package com.puppetlabs.http.client.impl;

import com.puppetlabs.certificate_authority.CertificateAuthority;
import com.puppetlabs.http.client.HttpClientException;
import com.puppetlabs.http.client.ClientOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

public class SslUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(SslUtils.class);

    private static void logAndRethrow(String msg, Throwable t) {
        LOGGER.error(msg, t);
        throw new HttpClientException(msg, t);
    }

    public static ClientOptions configureSsl(ClientOptions options) {
        if (options.getSslContext() != null) {
            return options;
        }

        try {
            FileReader crlsReader = null;
            String crls = options.getSslCrls();
            if (crls != null) {
                crlsReader = new FileReader(crls);
            }
            if ((options.getSslCert() != null) &&
                (options.getSslKey() != null) &&
                (options.getSslCaCert() != null)) {
                options.setSslContext(
                        CertificateAuthority.pemsToSSLContext(
                                new FileReader(options.getSslCert()),
                                new FileReader(options.getSslKey()),
                                new FileReader(options.getSslCaCert()),
                                crlsReader));

                options.setSslCert(null);
                options.setSslKey(null);
                options.setSslCaCert(null);
                options.setSslCrls(null);
            } else if (options.getSslCaCert() != null) {
                if (crls != null) {
                    options.setSslContext(
                            CertificateAuthority.caCertAndCrlPemsToSSLContext(
                                    new FileReader(options.getSslCaCert()),
                                    crlsReader));
                } else {
                    options.setSslContext(
                            CertificateAuthority.caCertPemToSSLContext(
                                    new FileReader(options.getSslCaCert())));
                }
                options.setSslCaCert(null);
                options.setSslCrls(null);
            }
        } catch (CRLException e) {
            logAndRethrow("Error while configuring SSL", e);
        } catch (KeyStoreException e) {
            logAndRethrow("Error while configuring SSL", e);
        } catch (CertificateException e) {
            logAndRethrow("Error while configuring SSL", e);
        } catch (InvalidAlgorithmParameterException e) {
            logAndRethrow("Error while configuring SSL", e);
        } catch (IOException e) {
            logAndRethrow("Error while configuring SSL", e);
        } catch (NoSuchAlgorithmException e) {
            logAndRethrow("Error while configuring SSL", e);
        } catch (KeyManagementException e) {
            logAndRethrow("Error while configuring SSL", e);
        } catch (UnrecoverableKeyException e) {
            logAndRethrow("Error while configuring SSL", e);
        }

        return options;
    }
}
