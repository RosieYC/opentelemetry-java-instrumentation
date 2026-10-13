/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.tooling.config;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.javaagent.extension.instrumentation.internal.AgentDistributionConfig;
import io.opentelemetry.javaagent.tooling.OpenTelemetryInstaller;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junitpioneer.jupiter.SetSystemProperty;

// the test task sets OTEL_TRACES_EXPORTER and OTEL_METRICS_EXPORTER to none, system properties
// take precedence over environment variables
@SetSystemProperty(key = "otel.traces.exporter", value = "otlp")
@SetSystemProperty(key = "otel.metrics.exporter", value = "none")
@SetSystemProperty(key = "otel.logs.exporter", value = "none")
@SetSystemProperty(key = "otel.exporter.otlp.protocol", value = "http/json")
class OtlpHttpInsecureSkipTlsVerifyTest {

  private static final char[] PASSWORD = "changeit".toCharArray();

  // the test JVM trusts a shared test certificate (javax.net.ssl.trustStore), so generate a new
  // self-signed one that is guaranteed not to be trusted
  private static SSLContext serverSslContext;

  private HttpsServer server;
  // request path -> content type
  private final Map<String, String> contentTypes = new ConcurrentHashMap<>();

  @BeforeAll
  static void createCertificate(@TempDir Path tempDir) throws Exception {
    Path keystorePath = tempDir.resolve("untrusted.p12");
    Process process =
        new ProcessBuilder(
                Paths.get(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair",
                "-alias",
                "server",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-dname",
                "CN=localhost",
                "-ext",
                "SAN=dns:localhost",
                "-validity",
                "1",
                "-storetype",
                "PKCS12",
                "-keystore",
                keystorePath.toString(),
                "-storepass",
                new String(PASSWORD))
            .redirectErrorStream(true)
            .start();
    assertThat(process.waitFor(60, SECONDS)).isTrue();
    assertThat(process.exitValue()).isZero();

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(keystorePath)) {
      keyStore.load(in, PASSWORD);
    }
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, PASSWORD);
    serverSslContext = SSLContext.getInstance("TLS");
    serverSslContext.init(kmf.getKeyManagers(), null, null);
  }

  @BeforeEach
  void setUp() throws Exception {
    GlobalOpenTelemetry.resetForTest();
    AgentDistributionConfig.resetForTest();

    server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
    server.setHttpsConfigurator(new HttpsConfigurator(serverSslContext));
    server.createContext(
        "/",
        exchange -> {
          contentTypes.put(
              exchange.getRequestURI().getPath(),
              exchange.getRequestHeaders().getFirst("Content-Type"));
          exchange.getRequestBody().close();
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    server.start();
    System.setProperty(
        "otel.exporter.otlp.endpoint", "https://localhost:" + server.getAddress().getPort());
  }

  @AfterEach
  void tearDown() {
    System.clearProperty("otel.exporter.otlp.endpoint");
    server.stop(0);
    GlobalOpenTelemetry.resetForTest();
    AgentDistributionConfig.resetForTest();
  }

  @Test
  void untrustedCertificateIsRejectedByDefault() {
    exportSpan();

    assertThat(contentTypes).isEmpty();
  }

  @SetSystemProperty(key = "otel.exporter.otlp.insecure-skip-tls-verify", value = "true")
  @Test
  void untrustedCertificateIsAcceptedWhenVerificationIsSkipped() {
    exportSpan();

    assertThat(contentTypes).containsEntry("/v1/traces", "application/json");
  }

  private static void exportSpan() {
    OpenTelemetrySdk sdk =
        OpenTelemetryInstaller.installOpenTelemetrySdk(
                OtlpHttpInsecureSkipTlsVerifyTest.class.getClassLoader())
            .getOpenTelemetrySdk();
    try {
      sdk.getTracer("test").spanBuilder("test-span").startSpan().end();
      sdk.getSdkTracerProvider().forceFlush().join(10, SECONDS);
    } finally {
      sdk.shutdown().join(10, SECONDS);
    }
  }
}
