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

import com.torchmind.padlock.metadata.AuthenticationClaimMetadata;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;

/**
 * Provides a base interface for metadata codecs.
 * @author Johannes Donath
 */
public interface IMetadataCodec {

        /**
         * Decodes authentication claim metadata.
         * @param type The metadata type.
         * @param encoded The encoded metadata.
         * @param <M> The metadata type.
         * @return The decoded metadata.
         */
        <M extends AuthenticationClaimMetadata> M decode (@Nonnull Class<M> type, @Nonnull ByteBuffer encoded);

        /**
         * Encodes authentication claim metadata.
         * @param type The metadata type.
         * @param decoded The decoded metadata.
         * @param <M> The metadata type.
         * @return The encoded metadata.
         */
        <M extends AuthenticationClaimMetadata> ByteBuffer encode (@Nonnull Class<M> type, @Nonnull M decoded);
}
