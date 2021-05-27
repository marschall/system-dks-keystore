package com.github.marschall.systemdkskeystore;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.junit.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URL;
import java.security.DomainLoadStoreParameter;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class DomainKeystoreTests {

  @Test
  void load() throws Exception {
    KeyStore keyStore = KeyStore.getInstance("DKS");
    URL dksResource = DomainKeystoreTests.class.getClassLoader().getResource("keystores/sample.dks");
    assertNotNull(dksResource);
    URI dksUri = new URI(dksResource.toExternalForm() + "#junit_protected");
    Map<String, ProtectionParameter> protectionParams = Collections.emptyMap();
    LoadStoreParameter loadStoreParameter = new DomainLoadStoreParameter(dksUri, protectionParams);
    keyStore.load(loadStoreParameter);

    System.out.println("keystore size: " + keyStore.size());
    System.out.println("aliases: " + Collections.list(keyStore.aliases()));
    assertTrue(keyStore.isCertificateEntry("bad_ssl_truststore self-signed")); // from the generated truststore
    assertTrue(keyStore.isCertificateEntry("bad_ssl_truststore untrusted-root")); // from the directory truststore

    assertTrue(keyStore.isCertificateEntry("system_truststore letsencryptisrgx1 [jdk]")); // from the JDK truststore
    assertTrue(keyStore.isCertificateEntry("system_truststore digicertglobalrootca [jdk]")); // from the JDK truststore

    List<String> aliases = Collections.list(keyStore.aliases());
    assertThat(aliases, hasSize(greaterThan(10))); // from the JDK truststore
  }

}
