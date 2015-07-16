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

import com.torchmind.padlock.security.AbstractDelegatingProvider;
import com.torchmind.padlock.security.IProvider;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Provides an implementation of {@link com.torchmind.padlock.security.verification.IVerificationProvider} that utilizes
 * asymmetric cryptography.
 * @author Johannes Donath
 */
public class AsymmetricVerificationProvider extends AbstractDelegatingProvider<Signature, PublicKey> implements IVerificationProvider<PublicKey> {

        public AsymmetricVerificationProvider (@Nonnull Signature provider, @Nonnull PublicKey key) throws IllegalArgumentException {
                super (provider, key);
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public IProvider<PublicKey> key (@Nonnull PublicKey key) throws IllegalArgumentException {
                try {
                        this.provider ().initVerify (key);
                        return super.key (key);
                } catch (InvalidKeyException ex) {
                        throw new IllegalArgumentException ("Invalid public key: " + ex.getMessage ());
                }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean verify (@Nonnull ByteBuffer metadata, @Nonnull ByteBuffer signature) {
                try {
                        this.provider ().update (metadata);

                        // extract signature - Thanks Oracle
                        byte[] signatureBytes = new byte[signature.remaining ()];
                        signature.get (signatureBytes);

                        return this.provider ().verify (signatureBytes);
                } catch (SignatureException ex) {
                        // a SignatureException cannot signify an invalid mode in our case - Thus we will just assume
                        // the signature is intentionally invalid
                        return false;
                }
        }
}
