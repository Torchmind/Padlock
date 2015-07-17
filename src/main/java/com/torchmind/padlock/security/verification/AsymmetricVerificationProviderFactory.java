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
package com.torchmind.padlock.security.verification;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Provides a factory for {@link com.torchmind.padlock.security.verification.AsymmetricVerificationProvider} instances.
 * @author Johannes Donath
 */
public class AsymmetricVerificationProviderFactory implements IVerificationProviderFactory {
        private final String algorithm;
        private final PublicKey publicKey;

        public AsymmetricVerificationProviderFactory (@Nonnull String algorithm, @Nonnull PublicKey publicKey) {
                this.algorithm = algorithm;
                this.publicKey = publicKey;
        }

        /**
         * Retrieves the signature algorithm.
         * @return The algorithm.
         */
        @Nonnull
        public String algorithm () {
                return this.algorithm;
        }

        /**
         * Retrieves the public key.
         * @return The key.
         */
        @Nonnull
        public PublicKey publicKey () {
                return this.publicKey;
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public AsymmetricVerificationProvider build () throws IllegalStateException {
                try {
                        return (new AsymmetricVerificationProvider (Signature.getInstance (this.algorithm ()), this.publicKey ()));
                } catch (NoSuchAlgorithmException ex) {
                        throw new IllegalStateException ("Unsupported asymmetric signature algorithm: " + ex.getMessage (), ex);
                }
        }
}
