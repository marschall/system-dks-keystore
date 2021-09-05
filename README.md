System DKS KeyStore
===================

Just like the DKS keystore but can be used as a system keystore.

Usage
-----

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


