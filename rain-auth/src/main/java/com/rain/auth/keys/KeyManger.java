package com.rain.auth.keys;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Component
public class KeyManger {

    /**
     * 生成RsaKey
     * @return
     * @throws Exception
     */
    public RSAKey rsaKey() throws Exception{
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        var keyPair = keyPairGenerator.generateKeyPair();
        var aPublic = (RSAPublicKey) keyPair.getPublic();
        var aPrivate = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(aPublic)
                .privateKey(aPrivate)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

}
