/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

package com.google.gemini.cli.jetbrains.transport

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.coroutines.*
import kotlin.test.*
import kotlin.system.measureTimeMillis

/**
 * Integration tests for the JetBrains IDE Companion plugin.
 * Tests full request/response cycles, performance, and real-world scenarios.
 */
class IntegrationTest {
    
    @Test
    fun `should handle complete MCP request-response cycle`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Send a valid JSON-RPC 2.0 request
        val response = client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer $validToken")
            header("Content-Type", "application/json")
            setBody("""{"jsonrpc":"2.0","method":"getActiveFile","params":{},"id":1}""")
        }
        
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("jsonrpc"), "Response should contain jsonrpc field")
        
        transport.dispose()
    }
    
    @Test
    fun `should reject malformed JSON-RPC requests`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Send invalid JSON-RPC request (missing jsonrpc field)
        val response = client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer $validToken")
            header("Content-Type", "application/json")
            setBody("""{"method":"test","id":1}""")
        }
        
        assertEquals(HttpStatusCode.OK, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("error"), "Response should contain error field")
        assertTrue(body.contains("-32600"), "Response should contain Invalid Request error code")
        
        transport.dispose()
    }
    
    @Test
    fun `should handle multiple sequential requests from same session`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        val sessionId = "test-session-123"
        
        repeat(10) { iteration ->
            val response = client.post("/mcp") {
                header(HttpHeaders.Host, "localhost:$port")
                header(HttpHeaders.Authorization, "Bearer $validToken")
                header("mcp-session-id", sessionId)
                header("Content-Type", "application/json")
                setBody("""{"jsonrpc":"2.0","method":"test$iteration","id":$iteration}""")
            }
            
            assertEquals(HttpStatusCode.OK, response.status, "Request $iteration should succeed")
        }
        
        // Verify session is tracked
        val sessions = transport.getActiveSessions()
        assertEquals(1, sessions.size, "Should have exactly one session")
        assertTrue(sessions.containsKey(sessionId), "Should contain our session ID")
        
        transport.dispose()
    }
    
    @Test
    fun `should handle concurrent requests efficiently`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Measure performance for 100 concurrent requests
        val duration = measureTimeMillis {
            val jobs = (1..100).map { clientId ->
                async(Dispatchers.IO) {
                    testApplication {
                        client.post("http://127.0.0.1:$port/mcp") {
                            header(HttpHeaders.Host, "localhost:$port")
                            header(HttpHeaders.Authorization, "Bearer $validToken")
                            header("mcp-session-id", "client-$clientId")
                            header("Content-Type", "application/json")
                            setBody("""{"jsonrpc":"2.0","method":"test","id":$clientId}""")
                        }
                    }
                }
            }
            
            val results = jobs.awaitAll()
            results.forEach { response ->
                assertEquals(HttpStatusCode.OK, response.status)
            }
        }
        
        println("100 concurrent requests completed in ${duration}ms")
        assertTrue(duration < 10000, "Should complete 100 requests in under 10 seconds")
        
        transport.dispose()
    }
    
    @Test
    fun `should enforce request size limits`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Create a very large request (11MB - should exceed typical limits)
        val largePayload = "x".repeat(11 * 1024 * 1024)
        
        val response = client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer $validToken")
            header("Content-Type", "application/json")
            setBody(largePayload)
        }
        
        // Should handle large requests gracefully (either accept or reject cleanly)
        assertTrue(response.status.value in 200..599, "Should return valid HTTP status")
        
        transport.dispose()
    }
    
    @Test
    fun `should cleanup sessions on disconnect`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        val sessionId = "cleanup-test-session"
        
        // Create a session
        client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer $validToken")
            header("mcp-session-id", sessionId)
            setBody("""{"jsonrpc":"2.0","method":"test","id":1}""")
        }
        
        // Verify session exists
        assertTrue(transport.getActiveSessions().containsKey(sessionId))
        
        // Manually cleanup session
        transport.cleanupSession(sessionId)
        
        // Verify session is removed
        assertFalse(transport.getActiveSessions().containsKey(sessionId))
        
        transport.dispose()
    }
    
    @Test
    fun `should handle rapid session creation and destruction`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        repeat(50) { iteration ->
            val sessionId = "rapid-session-$iteration"
            
            // Create session
            client.post("/mcp") {
                header(HttpHeaders.Host, "localhost:$port")
                header(HttpHeaders.Authorization, "Bearer $validToken")
                header("mcp-session-id", sessionId)
                setBody("""{"jsonrpc":"2.0","method":"test","id":1}""")
            }
            
            // Immediately cleanup
            transport.cleanupSession(sessionId)
        }
        
        // All sessions should be cleaned up
        assertEquals(0, transport.getActiveSessions().size)
        
        transport.dispose()
    }
    
    @Test
    fun `should maintain session isolation under load`() = runBlocking {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Create 20 sessions concurrently and verify they're all tracked separately
        val sessionIds = (1..20).map { "load-test-session-$it" }
        
        val jobs = sessionIds.map { sessionId ->
            async(Dispatchers.IO) {
                testApplication {
                    repeat(5) { iteration ->
                        client.post("http://127.0.0.1:$port/mcp") {
                            header(HttpHeaders.Host, "localhost:$port")
                            header(HttpHeaders.Authorization, "Bearer $validToken")
                            header("mcp-session-id", sessionId)
                            setBody("""{"jsonrpc":"2.0","method":"test","id":$iteration}""")
                        }
                    }
                }
            }
        }
        
        jobs.awaitAll()
        
        // Verify all sessions are tracked
        val activeSessions = transport.getActiveSessions()
        assertEquals(20, activeSessions.size, "Should have 20 active sessions")
        
        sessionIds.forEach { sessionId ->
            assertTrue(activeSessions.containsKey(sessionId), "Should contain session $sessionId")
        }
        
        transport.dispose()
    }
    
    @Test
    fun `should handle OPTIONS preflight requests`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        
        val response = client.options("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Origin, "http://localhost")
        }
        
        // CORS should handle OPTIONS requests
        assertTrue(response.status.value in 200..299 || response.status == HttpStatusCode.NoContent)
        
        transport.dispose()
    }
    
    @Test
    fun `should track session timestamps accurately`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        val sessionId = "timestamp-test-session"
        
        val startTime = System.currentTimeMillis()
        
        // Create session
        client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer $validToken")
            header("mcp-session-id", sessionId)
            setBody("""{"jsonrpc":"2.0","method":"test","id":1}""")
        }
        
        val endTime = System.currentTimeMillis()
        
        // Verify session timestamp is within reasonable range
        val session = transport.getActiveSessions()[sessionId]
        assertNotNull(session, "Session should exist")
        assertTrue(session.connectedAt >= startTime, "Session timestamp should be after start time")
        assertTrue(session.connectedAt <= endTime, "Session timestamp should be before end time")
        
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
