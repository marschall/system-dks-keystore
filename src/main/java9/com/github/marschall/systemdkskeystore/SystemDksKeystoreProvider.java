package com.github.marschall.systemdkskeystore;

import java.security.Provider;

public final class SystemDksKeystoreProvider extends Provider {

  /**
   * The name of this security provider.
   */
  public static final String NAME = "system-DKS";

  /**
   * The type of keystore that uses directories to store certificates.
   */
  public static final String TYPE = "system-DKS";

  public SystemDksKeystoreProvider() {
    super(NAME, "1.0.0", "system-DKS (KeyStore)");
  }

}
