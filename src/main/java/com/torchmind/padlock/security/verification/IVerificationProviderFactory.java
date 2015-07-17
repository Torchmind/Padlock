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

import com.torchmind.padlock.security.IProviderFactory;

import java.security.Key;

/**
 * Provides a factory for {@link com.torchmind.padlock.security.verification.IVerificationProvider} instances.
 * @author Johannes Donath
 */
@FunctionalInterface
public interface IVerificationProviderFactory<T extends IVerificationProvider> extends IProviderFactory<T> {
}
