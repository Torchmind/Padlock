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
package com.torchmind.padlock;

import com.torchmind.padlock.metadata.AuthenticationClaimMetadata;
import com.torchmind.padlock.metadata.codec.IMetadataCodec;
import com.torchmind.padlock.metadata.codec.JacksonMetadataCodec;
import com.torchmind.padlock.security.signature.ISignatureProvider;
import com.torchmind.padlock.security.verification.IVerificationProvider;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.security.SignatureException;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Provides access to the Padlock en/de-coders.
 * @author Johannes Donath
 */
@ThreadSafe
public final class Padlock {
        private final Lock lock = new ReentrantLock (true);

        private final Duration maximumValidityDuration;
        private final IMetadataCodec metadataCodec;
        private final ISignatureProvider signatureProvider;
        private final IVerificationProvider verificationProvider;

        private Padlock (@Nullable Duration maximumValidityDuration, @Nonnull IMetadataCodec metadataCodec, @Nullable ISignatureProvider signatureProvider, @Nullable IVerificationProvider verificationProvider) {
                this.maximumValidityDuration = maximumValidityDuration;
                this.metadataCodec = metadataCodec;
                this.signatureProvider = signatureProvider;
                this.verificationProvider = verificationProvider;
        }

        /**
         * Retrieves a {@link com.torchmind.padlock.Padlock} instance factory.
         * @return The factory.
         */
        public static Builder builder () {
                return (new Builder ());
        }

        /**
         * Decodes an authentication claim.
         * @param type The metadata type.
         * @param claim The encoded token.
         * @param <M> The metadata type.
         * @return The claim.
         * @throws java.lang.IllegalArgumentException when the claim is malformed.
         */
        @Nonnull
        public <M extends AuthenticationClaimMetadata> IAuthenticationClaim<M> decode (@Nonnull Class<M> type, @Nonnull String claim) throws IllegalArgumentException {
                int separatorIndex = claim.indexOf ('.');
                if (separatorIndex == -1) throw new IllegalArgumentException ("Missing signature separator in claim: " + claim);

                String encodedMetadata = claim.substring (0, separatorIndex);
                String encodedSignature = claim.substring ((separatorIndex + 1));

                Base64.Decoder decoder = Base64.getUrlDecoder ();
                ByteBuffer metadataBuffer = ByteBuffer.wrap (decoder.decode (encodedMetadata));
                ByteBuffer signatureBuffer = ByteBuffer.wrap (decoder.decode (encodedSignature));
                M metadata = this.metadataCodec ().decode (type, metadataBuffer);

                return (new AuthenticationClaim<> (type, metadata, signatureBuffer));
        }

        /**
         * Encodes an authentication claim.
         * @param claim The claim.
         * @param <M> The claim type.
         * @return The encoded claim.
         */
        public <M extends AuthenticationClaimMetadata> String encode (@Nonnull IAuthenticationClaim<M> claim) {
                byte[] metadataBytes;
                byte[] signatureBytes;

                {
                        ByteBuffer metadataBuffer = this.metadataCodec ().encode (claim.metadataType (), claim.metadata ());

                        metadataBytes = new byte[metadataBuffer.remaining ()];
                        metadataBuffer.get (metadataBytes);

                        metadataBuffer.rewind ();

                }

                {
                        ByteBuffer signatureBuffer = claim.signature ();

                        signatureBytes = new byte[signatureBuffer.remaining ()];
                        signatureBuffer.get (signatureBytes);

                        signatureBuffer.rewind ();
                }

                {
                        Base64.Encoder encoder = Base64.getUrlEncoder ();
                        return String.valueOf (encoder.encodeToString (metadataBytes)) + '.' + encoder.encodeToString (signatureBytes);
                }
        }

        /**
         * Signs an authentication claim.
         * @param metadataType The metadata type.
         * @param metadata The metadata.
         * @param <M> The metadata type.
         * @return The signed claim.
         * @throws java.lang.IllegalStateException when no signature provider is available.
         * @throws java.security.SignatureException when encoding the signature fails.
         */
        @Nonnull
        public <M extends AuthenticationClaimMetadata> IAuthenticationClaim<M> sign (@Nonnull Class<M> metadataType, @Nonnull M metadata) throws IllegalStateException, SignatureException {
                this.lock.lock ();

                try {
                        ISignatureProvider provider = this.signatureProvider ();
                        if (provider == null)
                                throw new IllegalStateException ("Cannot sign authentication claims: No signature provider available");

                        ByteBuffer metadataBuffer = this.metadataCodec ().encode (metadataType, metadata);
                        ByteBuffer signatureBuffer = provider.sign (metadataBuffer);

                        return (new AuthenticationClaim<> (metadataType, metadata, signatureBuffer));
                } finally {
                        this.lock.unlock ();
                }
        }

        /**
         * Verifies an authentication claim.
         * @param claim The claim.
         * @param <M> The claim metadata type.
         * @return True if valid.
         * @throws java.lang.IllegalStateException when no verification provider is available.
         */
        public <M extends AuthenticationClaimMetadata> boolean verify (@Nonnull IAuthenticationClaim<M> claim) throws IllegalStateException {
                this.lock.lock ();

                try {
                        IVerificationProvider provider = this.verificationProvider ();
                        if (provider == null)
                                throw new IllegalStateException ("Cannot verify authentication claims: No verification provider available");

                        ByteBuffer metadataBuffer = this.metadataCodec ().encode (claim.metadataType (), claim.metadata ());
                        ByteBuffer signatureBuffer = claim.signature ();

                        return provider.verify (metadataBuffer, signatureBuffer);
                } finally {
                        this.lock.unlock ();
                }
        }

        /**
         * Retrieves the maximum validity duration.
         * @return The duration.
         */
        @Nullable
        public Duration maximumValidityDuration () {
                return this.maximumValidityDuration;
        }

        /**
         * Retrieves the metadata codec.
         * @return The codec.
         */
        @Nonnull
        public IMetadataCodec metadataCodec () {
                return this.metadataCodec;
        }

        /**
         * Retrieves the signature provider.
         * @return The provider.
         */
        @Nullable
        public ISignatureProvider signatureProvider () {
                return this.signatureProvider;
        }

        /**
         * Retrieves the verification provider.
         * @return The provider.
         */
        @Nullable
        public IVerificationProvider verificationProvider () {
                return this.verificationProvider;
        }

        /**
         * Provides a factory for {@link com.torchmind.padlock.Padlock} instances.
         */
        public static class Builder implements Cloneable {
                private Duration maximumValidityDuration;
                private IMetadataCodec metadataCodec;
                private ISignatureProvider signatureProvider;
                private IVerificationProvider verificationProvider;

                protected Builder () {
                        this.reset ();
                }

                protected Builder (@Nullable Duration maximumValidityDuration, @Nullable IMetadataCodec metadataCodec, @Nullable ISignatureProvider signatureProvider, @Nullable IVerificationProvider verificationProvider) {
                        this.maximumValidityDuration (maximumValidityDuration);
                        this.metadataCodec (metadataCodec);
                        this.signatureProvider (signatureProvider);
                        this.verificationProvider (verificationProvider);
                }

                public Builder (@Nonnull Builder builder) {
                        this (builder.maximumValidityDuration (), builder.metadataCodec (), builder.signatureProvider (), builder.verificationProvider ());
                }

                /**
                 * Builds the {@link com.torchmind.padlock.Padlock} instance.
                 * @return The instance.
                 * @throws java.lang.IllegalStateException when the configuration is invalid.
                 */
                @Nonnull
                public Padlock build () throws IllegalStateException {
                        IMetadataCodec metadataCodec = this.metadataCodec ();
                        if (metadataCodec == null) metadataCodec = new JacksonMetadataCodec ();

                        try {
                                return (new Padlock (this.maximumValidityDuration (), metadataCodec, this.signatureProvider (), this.verificationProvider ()));
                        } finally {
                                this.reset ();
                        }
                }

                /**
                 * {@inheritDoc}
                 */
                @Override
                protected Builder clone () {
                        return (new Builder (this));
                }

                /**
                 * Resets the builder state.
                 * @return The builder.
                 */
                @Nonnull
                public Builder reset () {
                        this.maximumValidityDuration (Duration.ofDays (2));
                        this.metadataCodec (null);
                        this.signatureProvider (null);
                        this.verificationProvider (null);

                        return this;
                }

                /**
                 * Retrieves the maximum validity duration (rejects claims with longer durations).
                 * If {@code null}, period length checks are disabled.
                 * @return The duration.
                 */
                @Nullable
                public Duration maximumValidityDuration () {
                        return this.maximumValidityDuration;
                }

                /**
                 * Sets the maximum validity duration (rejects claim with longer durations).
                 * If {@code null}, period length checks are disabled.
                 * @param maximumValidityDuration The duration (or null).
                 * @return The builder.
                 */
                @Nonnull
                public Builder maximumValidityDuration (@Nullable Duration maximumValidityDuration) {
                        this.maximumValidityDuration = maximumValidityDuration;
                        return this;
                }

                /**
                 * Retrieves the metadata codec.
                 * <strong>Note:</strong> Defaults to {@link com.torchmind.padlock.metadata.codec.JacksonMetadataCodec} if set to {@code null}.
                 * @return The codec.
                 */
                @Nullable
                public IMetadataCodec metadataCodec () {
                        return this.metadataCodec;
                }

                /**
                 * Sets the metadata codec.
                 * <strong>Note:</strong> Defaults to {@link com.torchmind.padlock.metadata.codec.JacksonMetadataCodec} if set to {@code null}.
                 * @param metadataCodec The codec.
                 * @return The builder.
                 */
                @Nonnull
                public Builder metadataCodec (@Nullable IMetadataCodec metadataCodec) {
                        this.metadataCodec = metadataCodec;
                        return this;
                }

                /**
                 * Retrieves the signature provider.
                 * @return The provider.
                 */
                @Nullable
                public ISignatureProvider signatureProvider () {
                        return this.signatureProvider;
                }

                /**
                 * Sets the signature provider.
                 * @param signatureProvider The provider.
                 * @return The builder.
                 */
                @Nonnull
                public Builder signatureProvider (@Nullable ISignatureProvider signatureProvider) {
                        this.signatureProvider = signatureProvider;
                        return this;
                }

                /**
                 * Retrieves the verification provider.
                 * @return The provider.
                 */
                @Nullable
                public IVerificationProvider verificationProvider () {
                        return this.verificationProvider;
                }

                /**
                 * Sets the verification provider.
                 * @param verificationProvider The provider.
                 * @return The builder.
                 */
                @Nonnull
                public Builder verificationProvider (@Nullable IVerificationProvider verificationProvider) {
                        this.verificationProvider = verificationProvider;
                        return this;
                }
        }
}
