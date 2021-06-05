package com.github.marschall.systemdkskeystore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.DomainLoadStoreParameter;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;

/**
 * {@link KeyStoreSpi} implementation that delegates to a DKS key store.
 * <p>
 * Should not be called directly.
 */
public final class SystemDksKeystore extends KeyStoreSpi {

  private KeyStore delegate;

  /**
   * Default constructor.
   * <p>
   * Should not be called directly.
   */
  public SystemDksKeystore() {
    super();
  }

  @Override
  public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
    try {
      this.delegate.store(stream, password);
    } catch (KeyStoreException e) {
      throw new IOException("could not store keystore", e);
    }
  }

  @Override
  public void engineLoad(LoadStoreParameter param) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
    // intentionally don't close as caller has to close
    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(stream), 1024); // use default charset
    String location = PropertyReplacer.replaceProperties(bufferedReader.readLine());

    URI dksUri = toUri(location);
    Map<String, ProtectionParameter> protectionParams = Collections.emptyMap();
    LoadStoreParameter loadStoreParameter = new DomainLoadStoreParameter(dksUri, protectionParams);

    try {
      this.delegate = KeyStore.getInstance("DKS");
    } catch (KeyStoreException e) {
      throw new NoSuchAlgorithmException("DKS keystore type is unsupported", e);
    }
    this.delegate.load(loadStoreParameter);
  }

  private static URI toUri(String location) throws IOException {
    String resolved = PropertyReplacer.replaceProperties(location);
    if (!resolved.contains(":/")) {
      resolved = "file://" + resolved;
    }
    try {
      return new URI(resolved);
    } catch (URISyntaxException e) {
      throw new IOException("invalid URI:" + location, e);
    }
  }

  @Override
  public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
    try {
      return this.delegate.getKey(alias, password);
    } catch (KeyStoreException e) {
      UnrecoverableKeyException exception = new UnrecoverableKeyException("could not load key with alias: "  + alias);
      exception.initCause(e);
      throw exception;
    }
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    try {
      return this.delegate.getCertificateChain(alias);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not get certificate chain with alias: " + alias, e);
    }
  }

  @Override
  public Certificate engineGetCertificate(String alias) {
    try {
      return this.delegate.getCertificate(alias);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not get certificate with alias: " + alias, e);
    }
  }

  @Override
  public Date engineGetCreationDate(String alias) {
    try {
      return this.delegate.getCreationDate(alias);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not get creation date of alias: " + alias, e);
    }
  }

  @Override
  public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
    this.delegate.setKeyEntry(alias, key, password, chain);

  }

  @Override
  public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
    this.delegate.setKeyEntry(alias, key, chain);
  }

  @Override
  public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
    this.delegate.setCertificateEntry(alias, cert);
  }

  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    this.delegate.deleteEntry(alias);
  }

  @Override
  public Enumeration<String> engineAliases() {
    try {
      return this.delegate.aliases();
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not get aliases", e);
    }
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    try {
      return this.delegate.containsAlias(alias);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not get check for presence of alias: " + alias, e);
    }
  }

  @Override
  public int engineSize() {
    try {
      return this.delegate.size();
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not get keystore size", e);
    }
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    try {
      return this.delegate.isKeyEntry(alias);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not check entry with alias: " + alias, e);
    }
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    try {
      return this.delegate.isCertificateEntry(alias);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not check entry with alias: " + alias, e);
    }
  }

  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    try {
      return this.delegate.getCertificateAlias(cert);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not get alias of certificate", e);
    }
  }

  @Override
  public void engineStore(LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
    try {
      this.delegate.store(param);
    } catch (KeyStoreException e) {
      throw new IOException("could not store keystore", e);
    }
  }

  @Override
  public Entry engineGetEntry(String alias, ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
    return this.delegate.getEntry(alias, protParam);
  }

  @Override
  public void engineSetEntry(String alias, Entry entry, ProtectionParameter protParam) throws KeyStoreException {
    this.delegate.setEntry(alias, entry, protParam);
  }

  @Override
  public boolean engineEntryInstanceOf(String alias, Class<? extends Entry> entryClass) {
    try {
      return this.delegate.entryInstanceOf(alias, entryClass);
    } catch (KeyStoreException e) {
      throw new IllegalStateException("could not check entry with alias: " + alias, e);
    }
  }

}
