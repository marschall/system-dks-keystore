System DKS KeyStore
===================

Just like the DKS keystore but can be used as a system keystore.

Usage
-----

```xml
<dependency>
  <groupId>com.github.marschall</groupId>
  <artifactId>system-dks-keystore</artifactId>
  <version>1.0.0</version>
</dependency>
```

```
# register the system-DKS security provider
echo "security.provider.13=system-DKS" > additional.java.security

# create the redirect file that poins to the actual DKS file and domain
echo "sample.dks#domain_name" > keystore.redirect

java \
  -Djava.security.properties=additional.java.security \
  -Djavax.net.ssl.trustStore=keystore.redirect \
  -Djavax.net.ssl.trustStoreType=system-DKS
```

The system-dks-keystore JAR file must be on either the classpath or the modulepath.

Sample Domain
-------------

If you want to create a DKS truststore that contains the JDK truststore plus the certificates in an additional truststore (here named `plus.p12`) create a file called plus `plus.dks` with the following content:

```
domain system_plus {

    keystore plus
        eystoreType="PKCS12"
        keystorePasswordEnv="CHANGEIT"
        keystoreURI="${user.dir}/plus.p12";

    keystore system_truststore
        keystoreURI="${java.home}/lib/security/cacerts";

};
```

The `keystore.redirect` file should then contain `${user.dir}/plus.dks#system_plus`.


