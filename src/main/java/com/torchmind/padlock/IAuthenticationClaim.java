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

import javax.annotation.Nonnull;

/**
 * Represents an authentication claim.
 * @author Johannes Donath
 */
public interface IAuthenticationClaim<M extends AuthenticationClaimMetadata> {

        /**
         * Retrieves the claim metadata.
         * @return The metadata.
         */
        @Nonnull
        M metadata ();

        /**
         * Retrieves the claim signature.
         * @return The signature.
         */
        @Nonnull
        byte[] signature ();
}
