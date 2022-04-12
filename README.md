# kwai-apis

Public interfaces or tools for Kwai OpenId Connect APIs.
Security Check Passed. (auditor: linjiajun@kuaishou.com, developer: yaolei03@kuaishou.com)

* maven dependency

```xml
<dependency>
  <groupId>io.github.kwai-apis</groupId>
  <artifactId>kwai-oidc-client</artifactId>
  <version>1.0.3</version>
</dependency>
```

* usage

```
UrlJwkManager manager = new UrlJwkManager();
IdTokenVerifier verifier = new IdTokenVerifier.Builder(manager)
        .setAudience(Collections.singleton("Your clientId"))
        .build();

String idTokenString = "Your IdToken which received from token repsonse";
IdToken idToken = verifier.verify(idTokenString);
if (idToken == null) {
    // invalid idtoken
}

// validate notify params
Map<String,String> params = convertFromJson(json);
boolean pass = SignatureVerifier.checkSign(param, manager);
if (pass) {
    // sign pass
}

```
