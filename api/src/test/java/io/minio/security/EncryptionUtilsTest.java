package io.minio.security;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Random;

public class EncryptionUtilsTest {

    @Test
    public void canEncryptText() throws UnsupportedEncodingException, InvalidCipherTextException {
        byte[] randomData = "bar".getBytes("UTF-8");
        new Random().nextBytes(randomData);
        ByteBuffer encryptedData = EncryptionUtils.encrypt("foo", randomData);
        String hexData = BaseEncoding.base16().lowerCase().encode(encryptedData.array());
        ByteBuffer decryptedData = EncryptionUtils.decrypt("foo", encryptedData.array());
        Assert.assertArrayEquals(randomData, decryptedData.array());
    }

    @Test
    public void canDecryptText() throws UnsupportedEncodingException, InvalidCipherTextException {
        String key = "b55d0305a85cf4a8fd130d19098974da37b783dfff60248321316bd2387057c3";
        String hexData = "a2dc0836b0638b66e84c433855d08dad27bd3376f039b3c29286c8363b89c10d0008d56870f8c6de6d427362bd666ebe7416e592983b2222c30d9ee0";
        String additionalDataHex = "804B5DDA0007C5EDA395F0EAA96C57EEA1";
        EncryptionUtils.decrypt(BaseEncoding.base16().lowerCase().decode(key), BaseEncoding.base16().lowerCase().decode(hexData), BaseEncoding.base16().upperCase().decode(additionalDataHex));
    }

    @Test
    public void canDecryptText2() throws UnsupportedEncodingException, InvalidCipherTextException {
        String key = "foo";
        String hexData = "24be158f6979df2c4d08d8ab756855c042f0da885d8d4db0d3bf4acb978731d502827d4890c152a56b589817c99d37af7d7c2b5e808b8a5c2a79d5dd";
        EncryptionUtils.decrypt(key, BaseEncoding.base16().lowerCase().decode(hexData));
    }
}
