package io.minio.security;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.BCFKSLoadStoreParameter;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class EncryptionUtils {

    public static final int pbkdf2Cost = 8192;
    public static final byte pbkdf2AESGCM = 0x02;
    public static final byte argon2idAESGCM = 0x00;
    public static final byte argon2idChaCHa20Poly1305 = 0x01;

    public static final int NONCE_LENGTH = 8;
    public static final int SALT_LENGTH = 32;
    public static final int ID_LENGTH = 1;

    private static final SecureRandom random = new SecureRandom();

    private static byte[] random(int length) {
        byte[] data = new byte[length];
        random.nextBytes(data);
        return data;
    }

    public static ByteBuffer encrypt(String password, byte[] data) throws UnsupportedEncodingException, InvalidCipherTextException {
        byte[] nonce = random(NONCE_LENGTH);
        byte[] paddedNonce = new byte[NONCE_LENGTH + 4];
        System.arraycopy(nonce, 0, paddedNonce, 0, nonce.length);
        byte[] salt = random(SALT_LENGTH);

        byte[] key = new byte[32];
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_id).withSalt(salt).withMemoryAsKB(64).withParallelism(4).withIterations(1).build();
        generator.init(params);
        generator.generateBytes(password.getBytes("UTF-8"), key);

        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(true, new AEADParameters(new KeyParameter(key), 128, paddedNonce));
        int outputLength = cipher.getOutputSize(data.length);
        byte[] encryptedData = new byte[outputLength];
        int outputOffset = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        cipher.doFinal(encryptedData, outputOffset);
        ByteBuffer payload = ByteBuffer.allocate(1 + salt.length + nonce.length + outputLength);
        payload.put(salt);
        payload.put(pbkdf2AESGCM);
        payload.put(nonce);
        payload.put(encryptedData);
        return payload;
    }

    public static ByteBuffer decrypt(byte[] key, byte[] payload, byte[] additionalText) throws UnsupportedEncodingException, InvalidCipherTextException {
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payload);
        byte[] nonce = new byte[NONCE_LENGTH];
        byte[] paddedNonce = new byte[NONCE_LENGTH + 4];
        byte[] salt = new byte[SALT_LENGTH];
        payloadBuffer.get(salt);
        byte encryptionAlgo = payloadBuffer.get();
        payloadBuffer.get(nonce);
        byte[] encryptedData = new byte[payloadBuffer.remaining()];
        payloadBuffer.get(encryptedData);
        System.arraycopy(nonce, 0, paddedNonce, 0, nonce.length);
        paddedNonce[8] = 1;

        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(key), 128, paddedNonce, additionalText));
        int outputLength = cipher.getOutputSize(encryptedData.length);
        byte[] decryptedData = new byte[outputLength];
        int outputOffset = cipher.processBytes(encryptedData, 0, encryptedData.length, decryptedData, 0);
        outputOffset += cipher.doFinal(decryptedData, outputOffset);
        return ByteBuffer.wrap(decryptedData);
    }

    public static ByteBuffer decrypt(String password, byte[] payload) throws UnsupportedEncodingException, InvalidCipherTextException {
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payload);
        byte[] nonce = new byte[NONCE_LENGTH];
        byte[] paddedNonce = new byte[NONCE_LENGTH + 4];
        byte[] salt = new byte[SALT_LENGTH];
        payloadBuffer.get(salt);
        byte encryptionAlgo = payloadBuffer.get();
        payloadBuffer.get(nonce);
        byte[] encryptedData = new byte[payloadBuffer.remaining()];
        payloadBuffer.get(encryptedData);

        System.arraycopy(nonce, 0, paddedNonce, 0, nonce.length);

        byte[] key = new byte[32];
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_id).withSalt(salt).withMemoryAsKB(64).withParallelism(4).withIterations(1).build();
        generator.init(params);
        generator.generateBytes(password.getBytes("UTF-8"), key);

        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(key), 128, paddedNonce));
        int outputLength = cipher.getOutputSize(encryptedData.length);
        byte[] decryptedData = new byte[outputLength];
        int outputOffset = cipher.processBytes(encryptedData, 0, encryptedData.length, decryptedData, 0);
        outputOffset += cipher.doFinal(decryptedData, outputOffset);
        return ByteBuffer.wrap(decryptedData);
    }

    public static ByteBuffer encryptFips(String password, byte[] data) throws UnsupportedEncodingException, InvalidCipherTextException {
        byte[] nonce = random(NONCE_LENGTH);
        byte[] salt = random(SALT_LENGTH);
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password.getBytes("UTF-8"), salt, pbkdf2Cost);
        byte[] dk = ((KeyParameter) generator.generateDerivedParameters(256)).getKey();
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(true, new AEADParameters(new KeyParameter(dk), 128, nonce));
        int outputLength = cipher.getOutputSize(data.length);
        byte[] encryptedData = new byte[outputLength];
        int outputOffset = cipher.processBytes(data, 0, data.length, encryptedData, 0);
        cipher.doFinal(encryptedData, outputOffset);
        ByteBuffer payload = ByteBuffer.allocate(1 + salt.length + nonce.length + outputLength);
        payload.put(salt);
        payload.put(pbkdf2AESGCM);
        payload.put(nonce);
        payload.put(encryptedData);
        return payload;
    }

    public static ByteBuffer decryptFips(String password, byte[] payload) throws UnsupportedEncodingException, InvalidCipherTextException {
        ByteBuffer payloadBuffer = ByteBuffer.wrap(payload);
        byte[] nonce = new byte[NONCE_LENGTH];
        byte[] salt = new byte[SALT_LENGTH];
        payloadBuffer.get(salt);
        byte encryptionAlgo = payloadBuffer.get();
        payloadBuffer.get(nonce);
        byte[] encryptedData = new byte[payloadBuffer.remaining()];
        payloadBuffer.get(encryptedData);

        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        generator.init(password.getBytes("UTF-8"), salt, pbkdf2Cost);
        byte[] dk = ((KeyParameter) generator.generateDerivedParameters(256)).getKey();
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(dk), 128, nonce));
        int outputLength = cipher.getOutputSize(encryptedData.length);
        byte[] decryptedData = new byte[outputLength];
        int outputOffset = cipher.processBytes(encryptedData, 0, encryptedData.length, decryptedData, 0);
        outputOffset += cipher.doFinal(decryptedData, outputOffset);
        return ByteBuffer.wrap(decryptedData);
    }
}
