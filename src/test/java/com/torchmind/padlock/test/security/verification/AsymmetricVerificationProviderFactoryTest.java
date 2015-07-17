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
import com.torchmind.padlock.security.verification.AsymmetricVerificationProviderFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Provides test cases for {@link com.torchmind.padlock.security.verification.AsymmetricVerificationProviderFactory}.
 * @author Johannes Donath
 */
@RunWith (MockitoJUnitRunner.class)
public class AsymmetricVerificationProviderFactoryTest {
        public static final byte[] KEY_BYTES = new byte[] { 48, 92, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, 75, 0, 48, 72, 2, 65, 0, -119, 39, -112, 104, -47, -28, -19, -55, 9, 0, -42, -28, 96, 43, -14, -102, 74, -12, 30, 118, 91, -17, 12, 42, 45, -116, 115, -40, 42, 59, 10, 64, 95, 106, -78, -100, -15, -98, -17, -10, 78, 118, -114, -51, 91, -88, -58, -37, 33, -57, 64, -111, 55, 89, 119, 77, 21, 110, 90, -17, -124, 46, -100, 123, 2, 3, 1, 0, 1 };
        private PublicKey rsaKey;

        /**
         * Prepares the class for test cases contained herein.
         */
        @Before
        public void setup () throws NoSuchAlgorithmException, InvalidKeySpecException {
                KeyFactory factory = KeyFactory.getInstance ("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec (KEY_BYTES);
                rsaKey = factory.generatePublic (keySpec);
        }

        /**
         * Tests {@link com.torchmind.padlock.security.signature.AsymmetricSignatureProviderFactory#build()}.
         */
        @Test
        public void testBuild () {
                AsymmetricVerificationProviderFactory factory = new AsymmetricVerificationProviderFactory ("SHA1withRSA", this.rsaKey);

                AsymmetricVerificationProvider provider1 = factory.build ();
                AsymmetricVerificationProvider provider2 = factory.build ();

                Assert.assertNotNull (provider1);
                Assert.assertNotNull (provider2);
                Assert.assertNotEquals (provider1, provider2);
        }
}
