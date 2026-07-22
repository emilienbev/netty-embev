/*
 * Copyright 2026 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.testsuite.svm;

import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import java.io.InputStream;

/**
 * A tiny application that asserts BoringSSL/OpenSSL is available inside a native image and that both a
 * client and a server {@link SslContext} can be built with {@link SslProvider#OPENSSL}.
 *
 * <p>This exercises the fix for <a href="https://github.com/netty/netty/issues/11088">#11088</a>: without
 * the tcnative resource/JNI/run-time-init metadata and the {@code io.netty.handler.ssl} reverse-callback
 * JNI metadata, {@link OpenSsl#isAvailable()} returns {@code false} in a native image and building an
 * {@code OPENSSL} {@link SslContext} fails while the native code performs {@code GetMethodID} on the
 * netty callback classes.
 *
 * <p>The server certificate and key are loaded from bundled PEM resources (rather than generated at
 * run time) so the test stays focused on the OpenSSL/tcnative path and does not depend on run-time
 * certificate generation.
 */
public final class NativeImageOpenSsl {

    private static final String CERT = "openssl-test-cert.pem";
    private static final String KEY = "openssl-test-key.pem";

    /**
     * Main entry point (not instantiable)
     */
    private NativeImageOpenSsl() {
    }

    public static void main(String[] args) throws Exception {
        if (!OpenSsl.isAvailable()) {
            throw new IllegalStateException(
                    "OpenSsl.isAvailable() returned false in the native image", OpenSsl.unavailabilityCause());
        }
        System.out.println("OpenSsl.isAvailable()   = " + OpenSsl.isAvailable());
        System.out.println("OpenSsl.versionString() = " + OpenSsl.versionString());

        // Build a client OPENSSL SslContext - exercises the client-side reverse-callback classes
        // (certificate verification / session cache) that tcnative resolves via GetMethodID.
        SslContext clientContext = SslContextBuilder.forClient()
                .sslProvider(SslProvider.OPENSSL)
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
        if (clientContext.isServer()) {
            throw new IllegalStateException("Expected a client SslContext but got a server one");
        }
        System.out.println("client SslContext = " + clientContext.getClass().getName());

        // Build a server OPENSSL SslContext - exercises the server-side reverse-callback classes
        // (certificate callback, SNI hostname matcher, trust manager verify callback).
        try (InputStream cert = openResource(CERT);
             InputStream key = openResource(KEY)) {
            SslContext serverContext = SslContextBuilder.forServer(cert, key)
                    .sslProvider(SslProvider.OPENSSL)
                    .build();
            if (!serverContext.isServer()) {
                throw new IllegalStateException("Expected a server SslContext but got a client one");
            }
            System.out.println("server SslContext = " + serverContext.getClass().getName());
        }

        System.out.println("OpenSSL native-image smoke test passed");
    }

    private static InputStream openResource(String name) {
        InputStream in = NativeImageOpenSsl.class.getResourceAsStream(name);
        if (in == null) {
            throw new IllegalStateException("Missing bundled resource: " + name);
        }
        return in;
    }
}
