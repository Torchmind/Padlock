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

import javax.annotation.Nonnull;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Represents an authentication claim.
 * @author Johannes Donath
 */
public class AuthenticationClaim {
        private final UUID identifier;
        private Instant issuance;
        private Instant expiration;

        public AuthenticationClaim (@Nonnull UUID identifier, @Nonnull Instant issuance, @Nonnull Instant expiration) {
                this.identifier = identifier;
                this.issuance = issuance;
                this.expiration = expiration;
        }

        public AuthenticationClaim (@Nonnull UUID identifier, @Nonnull Instant issuance, @Nonnull Duration duration) {
                this (identifier, issuance, issuance.plus (duration));
        }

        public AuthenticationClaim (@Nonnull UUID identifier, @Nonnull Duration duration) {
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
        public AuthenticationClaim issuance (@Nonnull Instant issuance) {
                this.issuance = issuance;
                return this;
        }

        /**
         * Retrieves the claim expiration.
         * @return The expiration.
         */
        @Nonnull
        public Instant expiration () {
                return this.expiration;
        }

        /**
         * Sets the claim expiration.
         * @param expiration The expiration.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaim expiration (@Nonnull Instant expiration) {
                this.expiration = expiration;
                return this;
        }

        /**
         * Checks whether the claim has expired at a certain time.
         * @param instant The time.
         * @return True if expired.
         */
        public boolean expired (@Nonnull Instant instant) {
                return (!instant.isBefore (this.issuance) && !instant.isAfter (this.expiration));
        }

        /**
         * Checks whether the claim has expired at the current point of time.
         * @return True if expired.
         */
        public boolean expired () {
                return this.expired (Instant.now ());
        }

        /**
         * Retrieves the validity period.
         * @return The period.
         */
        @Nonnull
        public Duration validity () {
                return Duration.between (this.issuance (), this.expiration ());
        }

        /**
         * Sets the claim validity.
         * @param duration The validity duration.
         * @return The claim.
         */
        @Nonnull
        public AuthenticationClaim validity (@Nonnull Duration duration) {
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
        public AuthenticationClaim validity (@Nonnull Instant issuance, @Nonnull Duration duration) {
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
        public AuthenticationClaim validity (@Nonnull Instant issuance, @Nonnull Instant expiration) {
                this.issuance (issuance);
                return this.expiration (expiration);
        }
}
