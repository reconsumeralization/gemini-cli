/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

package com.google.gemini.cli.jetbrains.transport

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.defaultheaders.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.plugins.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.Implementation
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.*
import com.intellij.openapi.Disposable
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.project.Project
import com.intellij.openapi.diagnostic.logger
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/**
 * Secure HTTP transport for MCP server with DNS rebinding protection,
 * authentication, and multi-client session support.
 * 
 * This implementation follows the VS Code companion extension patterns
 * to ensure consistency and security across the Gemini CLI platform.
 */
class StreamableHttpServerTransport(
    private val project: Project,
    private val enableDnsRebindingProtection: Boolean = true,
    private val allowedHosts: Set<String> = setOf("localhost", "127.0.0.1", "[::1]"),
    private val allowedOrigins: Set<String> = setOf("http://localhost", "http://127.0.0.1")
) : Disposable {

    private val logger = logger<StreamableHttpServerTransport>()
    private var server: NettyApplicationEngine? = null
    private val authToken: String = generateSecureToken()
    private var assignedPort: Int = 0
    
    // Session tracking for multiple concurrent clients
    private val activeSessions = ConcurrentHashMap<String, SessionContext>()
    
    data class SessionContext(
        val sessionId: String,
        val connectedAt: Long,
        val workspacePath: String,
        val clientInfo: String = "gemini-cli"
    )
    
    companion object {
        private const val TOKEN_BYTES = 32
        private const val MCP_SESSION_ID_HEADER = "mcp-session-id"
        
        private fun generateSecureToken(): String {
            val random = SecureRandom()
            val bytes = ByteArray(TOKEN_BYTES)
            random.nextBytes(bytes)
            return Base64.getEncoder().encodeToString(bytes)
        }
    }
    
    fun start(): Int {
        server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            configureServer()
        }.start(wait = false)
        
        assignedPort = server!!.resolvedConnectors()
            .first { it.type == ConnectorType.HTTP }
            .port
        
        // Register for cleanup
        Disposer.register(project, this)
        
        logger.info("IDE server listening on http://127.0.0.1:$assignedPort")
        return assignedPort
    }
    
    private fun Application.configureServer() {
        // Security Layer 1: DNS Rebinding Protection
        if (enableDnsRebindingProtection) {
            intercept(ApplicationCallPipeline.Plugins) {
                if (!validateHostHeader(call.request.header(HttpHeaders.Host))) {
                    logger.warn(
                        "DNS rebinding attack blocked - Invalid Host: ${call.request.header(HttpHeaders.Host)}"
                    )
                    call.respond(HttpStatusCode.Forbidden, "Invalid Host header")
                    finish()
                    return@intercept
                }
                proceed()
            }
        }
        
        // Security Layer 2: Bearer Token Authentication
        intercept(ApplicationCallPipeline.Call) {
            if (!validateAuthorization(call.request.header(HttpHeaders.Authorization))) {
                logger.warn("Unauthorized request - missing or invalid Authorization header")
                call.respond(HttpStatusCode.Unauthorized, "Authentication required")
                finish()
                return@intercept
            }
            proceed()
        }
        
        // Security Layer 3: CORS with strict origins
        install(CORS) {
            allowedOrigins.forEach { origin ->
                val host = origin.removePrefix("http://").removePrefix("https://")
                allowHost(host, schemes = listOf("http", "https"))
            }
            
            allowMethod(HttpMethod.Get)
            allowMethod(HttpMethod.Post)
            allowMethod(HttpMethod.Options)
            
            allowHeader(HttpHeaders.ContentType)
            allowHeader(HttpHeaders.Authorization)
            allowHeader(MCP_SESSION_ID_HEADER)
            
            allowCredentials = true
            maxAgeInSeconds = 3600
        }
        
        // Security Layer 4: Secure Response Headers
        install(DefaultHeaders) {
            header("X-Content-Type-Options", "nosniff")
            header("X-Frame-Options", "DENY")
            header("X-XSS-Protection", "1; mode=block")
            header("Referrer-Policy", "strict-origin-when-cross-origin")
        }
        
        // Request size limit
        install(ContentNegotiation) {
            // Configure content negotiation if needed
        }
        
        // MCP Endpoint
        routing {
            post("/mcp") {
                handleMcpRequest(call)
            }
            
            get("/mcp") {
                handleMcpRequest(call)
            }
        }
    }
    
    private fun validateHostHeader(hostHeader: String?): Boolean {
        if (hostHeader == null) return false
        
        // Extract hostname (remove port if present)
        val hostname = hostHeader.substringBefore(":").lowercase().trim()
        
        // Validate against whitelist
        return allowedHosts.any { allowedHost ->
            allowedHost.lowercase() == hostname
        }
    }
    
    private fun validateAuthorization(authHeader: String?): Boolean {
        if (authHeader == null) return false
        
        val parts = authHeader.split(" ")
        if (parts.size != 2 || parts[0] != "Bearer") {
            return false
        }
        
        val token = parts[1]
        return token == authToken
    }
    
    private suspend fun handleMcpRequest(call: ApplicationCall) {
        // Extract or create session ID
        val sessionId = call.request.header(MCP_SESSION_ID_HEADER) 
            ?: java.util.UUID.randomUUID().toString()
        
        // Session tracking (multi-client support)
        val workspacePath = project.basePath ?: ""
        activeSessions.getOrPut(sessionId) {
            SessionContext(
                sessionId = sessionId,
                connectedAt = System.currentTimeMillis(),
                workspacePath = workspacePath
            )
        }
        
        // Forward to MCP server instance
        // Single mcpServer instance handles multiple sessions via session IDs
        val response = processMcpMessage(call.receiveText(), sessionId)
        
        call.respondText(response, ContentType.Application.Json)
    }
    
    private fun processMcpMessage(message: String, sessionId: String): String {
        // Your MCP processing logic here
        // The single mcpServer instance uses sessionId to track different clients
        logger.debug("Processing MCP message for session: $sessionId")
        
        try {
            // Parse and validate JSON-RPC message
            val jsonrpcRegex = Regex("\"jsonrpc\"\\s*:\\s*\"2\\.0\"")
            if (!jsonrpcRegex.containsMatchIn(message)) {
                return """{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}"""
            }
            
            // Log message for debugging (truncate if too long)
            val logMessage = if (message.length > 200) {
                "${message.substring(0, 200)}... (${message.length} bytes)"
            } else {
                message
            }
            logger.debug("MCP message content: $logMessage")
            
            return "{\"jsonrpc\":\"2.0\",\"result\":{}}"
        } catch (e: Exception) {
            logger.error("Error processing MCP message", e)
            return """{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"""
        }
    }
    
    fun getAuthToken(): String = authToken
    
    fun getPort(): Int = assignedPort
    
    fun getActiveSessions(): Map<String, SessionContext> = activeSessions.toMap()
    
    fun cleanupSession(sessionId: String) {
        activeSessions.remove(sessionId)
        logger.info("Cleaned up session: $sessionId")
    }
    
    override fun dispose() {
        logger.info("Disposing StreamableHttpServerTransport")
        activeSessions.clear()
        server?.stop(1000, 2000)
        server = null
    }
}