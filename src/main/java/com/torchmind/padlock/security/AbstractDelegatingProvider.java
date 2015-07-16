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
package com.torchmind.padlock.security;

import com.torchmind.padlock.security.AbstractProvider;

import javax.annotation.Nonnull;
import java.security.Key;

/**
 * Provides an abstract delegating {@link com.torchmind.padlock.security.IProvider} implementation.
 * @author Johannes Donath
 */
public abstract class AbstractDelegatingProvider<P, K extends Key> extends AbstractProvider<K> {
        private final P provider;

        public AbstractDelegatingProvider (@Nonnull P provider) {
                this.provider = provider;
        }

        /**
         * Retrieves the provider.
         * @return The provider.
         */
        @Nonnull
        public P provider () {
                return this.provider;
        }
}
