/*
 * Copyright 2015 Johannes Donath <johannesd@torchmind.com>
 * and other copyright owners as documented in the project's IP log.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.torchmind.padlock.test.security.verification;

import com.torchmind.padlock.security.verification.AsymmetricVerificationProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Provides test cases for {@link com.torchmind.padlock.security.verification.AsymmetricVerificationProvider}.
 * @author Johannes Donath
 */
@RunWith (MockitoJUnitRunner.class)
public class AsymmetricVerificationProviderTest {
        public static final byte[] TEST_BYTES = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        public static final byte[] TEST_BYTES_SIGNED = new byte[] { 9, -67, -6, -85, -100, -125, -88, -87, -38, 121, 103, 35, -103, -12, 45, 124, -23, 103, 17, 122, -59, 114, 5, -111, 13, 64, 56, 15, 117, 6, 14, 19, -100, -55, 88, -81, 116, 127, -113, -21, 72, 26, 65, 29, 36, 85, 127, -89, -112, 84, 13, -47, 88, -107, 67, -52, -6, 37, 96, -118, 92, 70, 122, 85 };
        public static final byte[] KEY_BYTES = new byte[] { 48, 92, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, 75, 0, 48, 72, 2, 65, 0, -119, 39, -112, 104, -47, -28, -19, -55, 9, 0, -42, -28, 96, 43, -14, -102, 74, -12, 30, 118, 91, -17, 12, 42, 45, -116, 115, -40, 42, 59, 10, 64, 95, 106, -78, -100, -15, -98, -17, -10, 78, 118, -114, -51, 91, -88, -58, -37, 33, -57, 64, -111, 55, 89, 119, 77, 21, 110, 90, -17, -124, 46, -100, 123, 2, 3, 1, 0, 1 };

        private PublicKey rsaKey;

        /**
         * Prepares the class for test cases contained herein.
         */
        @Before
        public void setupStatic () throws NoSuchAlgorithmException, InvalidKeySpecException {
                KeyFactory factory = KeyFactory.getInstance ("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec (KEY_BYTES);
                rsaKey = factory.generatePublic (keySpec);
        }

        /**
         * Tests {@link com.torchmind.padlock.security.signature.AsymmetricSignatureProvider#sign(java.nio.ByteBuffer)}.
         */
        @Test
        public void testSign () throws NoSuchAlgorithmException, SignatureException {
                AsymmetricVerificationProvider provider = new AsymmetricVerificationProvider (Signature.getInstance ("SHA1withRSA"), this.rsaKey);
                Assert.assertTrue (provider.verify (ByteBuffer.wrap (TEST_BYTES), ByteBuffer.wrap (TEST_BYTES_SIGNED)));
        }
}
