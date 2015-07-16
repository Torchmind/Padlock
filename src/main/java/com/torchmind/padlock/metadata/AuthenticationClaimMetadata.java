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
package com.torchmind.padlock.metadata;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Represents metadata stored within an authentication claim.
 * @author Johannes Donath
 */
@JsonAutoDetect (fieldVisibility = JsonAutoDetect.Visibility.ANY, creatorVisibility = JsonAutoDetect.Visibility.NONE, getterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE)
public class AuthenticationClaimMetadata {
        private final UUID identifier;
        private Instant issuance;
        private Instant expiration;

        private AuthenticationClaimMetadata () {
                this.identifier = null;
        }

        public AuthenticationClaimMetadata (@Nonnull UUID identifier, @Nonnull Instant issuance, @Nullable Instant expiration) {
                this.identifier = identifier;
                this.issuance = issuance;
                this.expiration = expiration;
        }

        public AuthenticationClaimMetadata (@Nonnull UUID identifier, @Nonnull Instant issuance, @Nonnull Duration duration) {
                this (identifier, issuance, issuance.plus (duration));
        }

        public AuthenticationClaimMetadata (@Nonnull UUID identifier, @Nonnull Duration duration) {
                this (identifier, Instant.now (), duration);
        }

        /**
         * Retrieves the claim identifier.
         * @return The identifier.
         */
        @Nonnull
        public UUID identifier () {
                return this.identifier;
        }

        /**
         * Retrieves the claim issuance.
         * @return The issuance.
         */
        @Nonnull
        public Instant issuance () {
                return this.issuance;
        }

        /**
         * Sets the issuance date.
         * @param issuance The issuance.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata issuance (@Nonnull Instant issuance) {
                this.issuance = issuance;
                return this;
        }

        /**
         * Retrieves the claim expiration.
         * @return The expiration.
         */
        @Nullable
        public Instant expiration () {
                return this.expiration;
        }

        /**
         * Sets the claim expiration.
         * @param expiration The expiration.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata expiration (@Nullable Instant expiration) {
                this.expiration = expiration;
                return this;
        }

        /**
         * Checks whether the claim has expired at a certain time.
         * @param instant The time.
         * @return True if expired.
         */
        public boolean expired (@Nonnull Instant instant) {
                if (instant.isBefore (this.issuance)) return true;
                if (this.expiration () == null) return false;
                return (!instant.isAfter (this.expiration));
        }

        /**
         * Checks whether the claim has expired at the current point of time.
         * @return True if expired.
         */
        public boolean expired () {
                return this.expired (Instant.now ());
        }

        /**
         * Checks whether the claim expires at a certain point of time.
         * @return True if claim expires.
         */
        public boolean expires () {
                return (this.expiration () != null);
        }

        /**
         * Checks whether the claim is not yet valid at a certain point of time.
         * @param instant The time.
         * @return True if not yet valid.
         */
        public boolean notYetValid (@Nonnull Instant instant) {
                return instant.isBefore (this.issuance ());
        }

        /**
         * Checks whether the claim is not yet valid.
         * @return True if not yet valid.
         */
        public boolean notYetValid () {
                return this.notYetValid (Instant.now ());
        }

        /**
         * Checks whether the claim is valid at a certain point of time.
         * @param instant The time.
         * @return True if valid.
         */
        public boolean valid (@Nonnull Instant instant) {
                return (!this.notYetValid (instant) && !this.expired (instant));
        }

        /**
         * Checks whether the claim is valid.
         * @return The time.
         */
        public boolean valid () {
                return this.valid (Instant.now ());
        }

        /**
         * Executes {@code consumer} when the claim has expired at a certain point of time.
         * @param instant The time.
         * @param consumer The consumer.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata ifExpired (@Nonnull Instant instant, @Nonnull Consumer<AuthenticationClaimMetadata> consumer) {
                if (this.expired (instant)) consumer.accept (this);
                return this;
        }

        /**
         * Executes {@code consumer} when the claim has expired.
         * @param consumer The consumer.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata ifExpired (@Nonnull Consumer<AuthenticationClaimMetadata> consumer) {
                if (this.expired ()) consumer.accept (this);
                return this;
        }

        /**
         * Executes {@code consumer} when the claim is valid at a certain point of time.
         * @param instant The time.
         * @param consumer The consumer.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata ifValid (@Nonnull Instant instant, @Nonnull Consumer<AuthenticationClaimMetadata> consumer) {
                if (this.valid (instant)) consumer.accept (this);
                return this;
        }

        /**
         * Executes {@code consumer} when the claim is valid.
         * @param consumer The consumer.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata ifValid (@Nonnull Consumer<AuthenticationClaimMetadata> consumer) {
                if (this.valid ()) consumer.accept (this);
                return this;
        }

        /**
         * Retrieves the validity period.
         * <strong>Note:</strong> If no expiration is set, a zero-length duration is returned.
         * @return The period.
         */
        @Nonnull
        public Duration validity () {
                if (this.expiration () == null) return Duration.ZERO;
                return Duration.between (this.issuance (), this.expiration ());
        }

        /**
         * Sets the claim validity.
         * @param duration The validity duration.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata validity (@Nonnull Duration duration) {
                this.expiration (this.issuance ().plus (duration));
                return this;
        }

        /**
         * Sets the claim validity.
         * @param issuance The issuance date.
         * @param duration The validity duration.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata validity (@Nonnull Instant issuance, @Nonnull Duration duration) {
                this.issuance (issuance);
                return this.validity (duration);
        }

        /**
         * Sets the claim validity.
         * @param issuance The issuance date.
         * @param expiration The expiration date.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaimMetadata validity (@Nonnull Instant issuance, @Nonnull Instant expiration) {
                this.issuance (issuance);
                return this.expiration (expiration);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean equals (Object o) {
                if (this == o) { return true; }
                if (!(o instanceof AuthenticationClaimMetadata)) { return false; }

                AuthenticationClaimMetadata that = (AuthenticationClaimMetadata) o;

                if (!identifier.equals (that.identifier)) { return false; }
                if (!issuance.equals (that.issuance)) { return false; }
                return !(expiration != null ? !expiration.equals (that.expiration) : that.expiration != null);

        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int hashCode () {
                int result = identifier.hashCode ();
                result = 31 * result + issuance.hashCode ();
                result = 31 * result + (expiration != null ? expiration.hashCode () : 0);
                return result;
        }
}
