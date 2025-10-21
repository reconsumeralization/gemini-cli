/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

package com.google.gemini.cli.jetbrains.transport

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.coroutines.*
import kotlin.test.*
import kotlin.system.measureTimeMillis

/**
 * Performance and load testing for the JetBrains IDE Companion plugin.
 * Validates performance characteristics and resource usage.
 */
class PerformanceTest {
    
    @Test
    fun `should handle 1000 requests in under 30 seconds`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        val duration = measureTimeMillis {
            val jobs = (1..1000).map { requestId ->
                async(Dispatchers.IO) {
                    testApplication {
                        client.post("http://127.0.0.1:$port/mcp") {
                            header(HttpHeaders.Host, "localhost:$port")
                            header(HttpHeaders.Authorization, "Bearer $validToken")
                            header("mcp-session-id", "perf-test-${requestId % 100}")
                            setBody("""{"jsonrpc":"2.0","method":"test","id":$requestId}""")
                        }
                    }
                }
            }
            
            val results = jobs.awaitAll()
            assertEquals(1000, results.count { it.status == HttpStatusCode.OK })
        }
        
        println("1000 requests completed in ${duration}ms (${1000.0 / duration * 1000} req/sec)")
        assertTrue(duration < 30000, "Should complete 1000 requests in under 30 seconds")
        
        transport.dispose()
    }
    
    @Test
    fun `should maintain low latency under moderate load`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        val latencies = mutableListOf<Long>()
        
        repeat(100) { iteration ->
            val latency = measureTimeMillis {
                testApplication {
                    client.post("http://127.0.0.1:$port/mcp") {
                        header(HttpHeaders.Host, "localhost:$port")
                        header(HttpHeaders.Authorization, "Bearer $validToken")
                        setBody("""{"jsonrpc":"2.0","method":"test","id":$iteration}""")
                    }
                }
            }
            latencies.add(latency)
        }
        
        val avgLatency = latencies.average()
        val maxLatency = latencies.maxOrNull() ?: 0L
        val p95Latency = latencies.sorted()[94] // 95th percentile
        
        println("Latency stats: avg=${avgLatency}ms, max=${maxLatency}ms, p95=${p95Latency}ms")
        assertTrue(avgLatency < 100, "Average latency should be under 100ms")
        assertTrue(p95Latency < 200, "95th percentile latency should be under 200ms")
        
        transport.dispose()
    }
    
    @Test
    fun `should handle burst traffic gracefully`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Simulate 3 bursts of 50 requests each
        repeat(3) { burstNumber ->
            val burstDuration = measureTimeMillis {
                val jobs = (1..50).map { requestId ->
                    async(Dispatchers.IO) {
                        testApplication {
                            client.post("http://127.0.0.1:$port/mcp") {
                                header(HttpHeaders.Host, "localhost:$port")
                                header(HttpHeaders.Authorization, "Bearer $validToken")
                                header("mcp-session-id", "burst-$burstNumber-$requestId")
                                setBody("""{"jsonrpc":"2.0","method":"test","id":$requestId}""")
                            }
                        }
                    }
                }
                
                val results = jobs.awaitAll()
                assertEquals(50, results.count { it.status == HttpStatusCode.OK })
            }
            
            println("Burst $burstNumber completed in ${burstDuration}ms")
            
            // Small delay between bursts
            delay(100)
        }
        
        transport.dispose()
    }
    
    @Test
    fun `should not leak memory with many sessions`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Create 100 sessions
        repeat(100) { iteration ->
            testApplication {
                client.post("http://127.0.0.1:$port/mcp") {
                    header(HttpHeaders.Host, "localhost:$port")
                    header(HttpHeaders.Authorization, "Bearer $validToken")
                    header("mcp-session-id", "mem-test-$iteration")
                    setBody("""{"jsonrpc":"2.0","method":"test","id":1}""")
                }
            }
        }
        
        // Verify all sessions are tracked
        assertEquals(100, transport.getActiveSessions().size)
        
        // Cleanup all sessions
        (0..99).forEach { iteration ->
            transport.cleanupSession("mem-test-$iteration")
        }
        
        // Verify all sessions are removed
        assertEquals(0, transport.getActiveSessions().size)
        
        transport.dispose()
    }
    
    @Test
    fun `should handle concurrent session creation efficiently`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        val duration = measureTimeMillis {
            val jobs = (1..200).map { sessionId ->
                async(Dispatchers.IO) {
                    testApplication {
                        client.post("http://127.0.0.1:$port/mcp") {
                            header(HttpHeaders.Host, "localhost:$port")
                            header(HttpHeaders.Authorization, "Bearer $validToken")
                            header("mcp-session-id", "concurrent-$sessionId")
                            setBody("""{"jsonrpc":"2.0","method":"test","id":1}""")
                        }
                    }
                }
            }
            
            jobs.awaitAll()
        }
        
        println("200 concurrent session creations in ${duration}ms")
        assertEquals(200, transport.getActiveSessions().size)
        assertTrue(duration < 10000, "Should create 200 sessions in under 10 seconds")
        
        transport.dispose()
    }
    
    @Test
    fun `should maintain consistent performance across different payload sizes`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        val payloadSizes = listOf(100, 1000, 10000, 100000) // bytes
        
        payloadSizes.forEach { size ->
            val payload = "x".repeat(size)
            val request = """{"jsonrpc":"2.0","method":"test","params":{"data":"$payload"},"id":1}"""
            
            val duration = measureTimeMillis {
                testApplication {
                    client.post("http://127.0.0.1:$port/mcp") {
                        header(HttpHeaders.Host, "localhost:$port")
                        header(HttpHeaders.Authorization, "Bearer $validToken")
                        setBody(request)
                    }
                }
            }
            
            println("Payload size ${size} bytes processed in ${duration}ms")
            assertTrue(duration < 5000, "Should process ${size} byte payload in under 5 seconds")
        }
        
        transport.dispose()
    }
    
    @Test
    fun `should recover from temporary overload`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Phase 1: Overload with 500 concurrent requests
        val overloadJobs = (1..500).map { requestId ->
            async(Dispatchers.IO) {
                testApplication {
                    try {
                        client.post("http://127.0.0.1:$port/mcp") {
                            header(HttpHeaders.Host, "localhost:$port")
                            header(HttpHeaders.Authorization, "Bearer $validToken")
                            header("mcp-session-id", "overload-$requestId")
                            setBody("""{"jsonrpc":"2.0","method":"test","id":1}""")
                        }
                    } catch (e: Exception) {
                        // Some requests might fail under overload - that's expected
                        null
                    }
                }
            }
        }
        
        overloadJobs.awaitAll()
        delay(1000) // Let system recover
        
        // Phase 2: Verify system recovers and handles normal load
        val recoveryJobs = (1..10).map { requestId ->
            async(Dispatchers.IO) {
                testApplication {
                    client.post("http://127.0.0.1:$port/mcp") {
                        header(HttpHeaders.Host, "localhost:$port")
                        header(HttpHeaders.Authorization, "Bearer $validToken")
                        header("mcp-session-id", "recovery-$requestId")
                        setBody("""{"jsonrpc":"2.0","method":"test","id":1}""")
                    }
                }
            }
        }
        
        val results = recoveryJobs.awaitAll()
        assertEquals(10, results.count { it.status == HttpStatusCode.OK }, 
            "System should recover and handle normal load after overload")
        
        transport.dispose()
    }
    
    private fun mockProject(): com.intellij.openapi.project.Project {
        return object : com.intellij.openapi.project.Project {
            override fun getName(): String = "test-project"
            override fun getBasePath(): String? = "/test/path"
            override fun getProjectFilePath(): String? = null
            override fun getWorkspaceFile(): com.intellij.openapi.vfs.VirtualFile? = null
            override fun getProjectFile(): com.intellij.openapi.vfs.VirtualFile? = null
            override fun getProjectDir(): com.intellij.openapi.vfs.VirtualFile? = null
            override fun getLocationHash(): String = "test-hash"
            override fun getLocation(): String = "/test/location"
            override fun isDefault(): Boolean = false
            override fun isInitialized(): Boolean = true
            override fun isDisposed(): Boolean = false
            override fun getService(serviceClass: Class<*>): Any? = null
            override fun <T : Any> getService(serviceClass: Class<T>, createIfNeeded: Boolean): T? = null
            override fun getComponent(interfaceClass: Class<*>): Any? = null
            override fun <T : Any> getComponent(interfaceClass: Class<T>, createIfNeeded: Boolean): T? = null
            override fun dispose() {}
        }
    }
}
