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
import kotlin.test.*

class SecurityValidationTest {
    
    @Test
    fun `should reject DNS rebinding attack`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        
        val response = client.get("/mcp") {
            header(HttpHeaders.Host, "evil.com:$port")
            header(HttpHeaders.Authorization, "Bearer ${transport.getAuthToken()}")
        }
        
        assertEquals(HttpStatusCode.Forbidden, response.status)
        transport.dispose()
    }
    
    @Test
    fun `should require bearer token`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        
        val response = client.get("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            // No Authorization header
        }
        
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        transport.dispose()
    }
    
    @Test
    fun `should validate allowed hosts`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        val validHosts = listOf(
            "localhost:$port",
            "127.0.0.1:$port",
            "[::1]:$port"
        )
        
        validHosts.forEach { host ->
            val response = client.get("/mcp") {
                header(HttpHeaders.Host, host)
                header(HttpHeaders.Authorization, "Bearer $validToken")
            }
            
            assertEquals(
                HttpStatusCode.OK, 
                response.status,
                "Should accept valid host: $host"
            )
        }
        transport.dispose()
    }
    
    @Test
    fun `should reject invalid tokens`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        
        val response = client.get("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer wrong-token")
        }
        
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        transport.dispose()
    }
    
    @Test
    fun `should reject malformed authorization header`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        
        val response = client.get("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "InvalidFormat token")
        }
        
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        transport.dispose()
    }
    
    @Test
    fun `should handle multiple concurrent clients`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        val clientCount = 10
        val clients = (1..clientCount).map { clientId ->
            client.get("/mcp") {
                header(HttpHeaders.Host, "localhost:$port")
                header(HttpHeaders.Authorization, "Bearer $validToken")
                header("mcp-session-id", "client-$clientId")
            }
        }
        
        // All clients should receive successful responses
        clients.forEach { response ->
            assertEquals(HttpStatusCode.OK, response.status)
        }
        
        // Verify session tracking
        val activeSessions = transport.getActiveSessions()
        assertEquals(clientCount, activeSessions.size)
        
        transport.dispose()
    }
    
    @Test
    fun `should prevent session bleed between clients`() = testApplication {
        val transport = StreamableHttpServerTransport(
            project = mockProject(),
            enableDnsRebindingProtection = true
        )
        
        val port = transport.start()
        val validToken = transport.getAuthToken()
        
        // Client 1 sets some state
        client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer $validToken")
            header("mcp-session-id", "client-1")
            setBody("""{"method": "setState", "params": {"value": "secret1"}}""")
        }
        
        // Client 2 tries to read state
        val response = client.post("/mcp") {
            header(HttpHeaders.Host, "localhost:$port")
            header(HttpHeaders.Authorization, "Bearer $validToken")
            header("mcp-session-id", "client-2")
            setBody("""{"method": "getState"}""")
        }
        
        // Should not receive Client 1's state
        val responseText = response.bodyAsText()
        assertFalse(responseText.contains("secret1"))
        
        transport.dispose()
    }
    
    private fun mockProject(): com.intellij.openapi.project.Project {
        // Mock project implementation for testing
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
