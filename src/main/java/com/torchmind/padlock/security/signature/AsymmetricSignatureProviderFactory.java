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
package com.torchmind.padlock.security.signature;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;

/**
 * Provides a factory for {@link com.torchmind.padlock.security.signature.AsymmetricSignatureProvider} instances.
 * @author Johannes Donath
 */
public class AsymmetricSignatureProviderFactory implements ISignatureProviderFactory {
        private final String algorithm;
        private final PrivateKey privateKey;

        public AsymmetricSignatureProviderFactory (@Nonnull String algorithm, @Nonnull PrivateKey privateKey) {
                this.algorithm = algorithm;
                this.privateKey = privateKey;
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
         * Retrieves the private key.
         * @return The key.
         */
        @Nonnull
        public PrivateKey privateKey () {
                return this.privateKey;
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public AsymmetricSignatureProvider build () throws IllegalStateException {
                try {
                        return new AsymmetricSignatureProvider (Signature.getInstance (this.algorithm ()), this.privateKey ());
                } catch (NoSuchAlgorithmException ex) {
                        throw new IllegalStateException ("Unsupported asymmetric signature algorithm: " + ex.getMessage (), ex);
                }
        }
}
