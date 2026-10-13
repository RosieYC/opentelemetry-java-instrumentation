/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.javaagent.tooling.config;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.javaagent.extension.instrumentation.internal.AgentDistributionConfig;
import io.opentelemetry.javaagent.tooling.OpenTelemetryInstaller;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.SetSystemProperty;

// the test task sets OTEL_TRACES_EXPORTER and OTEL_METRICS_EXPORTER to none, system properties
// take precedence over environment variables
@SetSystemProperty(key = "otel.traces.exporter", value = "otlp")
@SetSystemProperty(key = "otel.metrics.exporter", value = "otlp")
@SetSystemProperty(key = "otel.logs.exporter", value = "otlp")
class OtlpHttpJsonProtocolCustomizerProviderTest {

  private HttpServer server;
  // request path -> content type
  private final Map<String, String> contentTypes = new ConcurrentHashMap<>();
  // request path -> request body
  private final Map<String, String> bodies = new ConcurrentHashMap<>();

  @BeforeEach
  void setUp() throws IOException {
    GlobalOpenTelemetry.resetForTest();
    AgentDistributionConfig.resetForTest();

    server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          String path = exchange.getRequestURI().getPath();
          contentTypes.put(path, exchange.getRequestHeaders().getFirst("Content-Type"));
          bodies.put(path, readAll(exchange.getRequestBody()));
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    server.start();
    System.setProperty(
        "otel.exporter.otlp.endpoint", "http://localhost:" + server.getAddress().getPort());
  }

  @AfterEach
  void tearDown() {
    System.clearProperty("otel.exporter.otlp.endpoint");
    server.stop(0);
    GlobalOpenTelemetry.resetForTest();
    AgentDistributionConfig.resetForTest();
  }

  @SetSystemProperty(key = "otel.exporter.otlp.protocol", value = "http/json")
  @Test
  void httpJsonForAllSignals() {
    exportAllSignals();

    assertThat(contentTypes)
        .containsEntry("/v1/traces", "application/json")
        .containsEntry("/v1/metrics", "application/json")
        .containsEntry("/v1/logs", "application/json");
    assertThat(bodies.get("/v1/traces")).startsWith("{").contains("\"resourceSpans\"");
    assertThat(bodies.get("/v1/metrics")).startsWith("{").contains("\"resourceMetrics\"");
    assertThat(bodies.get("/v1/logs")).startsWith("{").contains("\"resourceLogs\"");
  }

  @SetSystemProperty(key = "otel.exporter.otlp.traces.protocol", value = "http/json")
  @Test
  void httpJsonForTracesOnly() {
    exportAllSignals();

    assertThat(contentTypes)
        .containsEntry("/v1/traces", "application/json")
        .containsEntry("/v1/metrics", "application/x-protobuf")
        .containsEntry("/v1/logs", "application/x-protobuf");
  }

  @Test
  void defaultIsHttpProtobuf() {
    exportAllSignals();

    assertThat(contentTypes)
        .containsEntry("/v1/traces", "application/x-protobuf")
        .containsEntry("/v1/metrics", "application/x-protobuf")
        .containsEntry("/v1/logs", "application/x-protobuf");
  }

  private void exportAllSignals() {
    OpenTelemetrySdk sdk =
        OpenTelemetryInstaller.installOpenTelemetrySdk(this.getClass().getClassLoader())
            .getOpenTelemetrySdk();
    try {
      sdk.getTracer("test").spanBuilder("test-span").startSpan().end();
      sdk.getMeter("test").counterBuilder("test-counter").build().add(1);
      sdk.getLogsBridge().get("test").logRecordBuilder().setBody("test-log").emit();

      sdk.getSdkTracerProvider().forceFlush().join(10, SECONDS);
      sdk.getSdkMeterProvider().forceFlush().join(10, SECONDS);
      sdk.getSdkLoggerProvider().forceFlush().join(10, SECONDS);
    } finally {
      sdk.shutdown().join(10, SECONDS);
    }
  }

  private static String readAll(InputStream inputStream) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int read;
    while ((read = inputStream.read(buffer)) != -1) {
      out.write(buffer, 0, read);
    }
    return new String(out.toByteArray(), UTF_8);
  }
}
