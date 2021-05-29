package com.github.marschall.systemdkskeystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class DomainKeystoreTests {

  static List<String> urls() {
    return Arrays.asList("https://sha256.badssl.com/", "https://self-signed.badssl.com/", "https://untrusted-root.badssl.com/");
  }

  @ParameterizedTest
  @MethodSource("urls")
  void urlConnection(String url) throws IOException {

    URLConnection connection = new URL(url).openConnection();
    assertTrue(connection instanceof HttpsURLConnection);
    connection.connect();
    try (InputStream inputStream = connection.getInputStream()) {
      assertNotNull(inputStream);
    }
  }

  @Test
  void systemDefaultTruststore() {
    String defaultTruststore = System.getProperty("javax.net.ssl.trustStore");
    assertNotNull(defaultTruststore);
    assertFalse(defaultTruststore.isEmpty());
    assertEquals("DKS", defaultTruststore);
  }

}
