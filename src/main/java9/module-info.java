module com.github.marschall.systemdkskeystore {

  exports com.github.marschall.systemdkskeystore;

  provides java.security.Provider
      with com.github.marschall.systemdkskeystore.SystemDksKeystoreProvider;

}