/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

package com.google.gemini.cli.jetbrains

import com.intellij.openapi.components.Service
import com.intellij.openapi.project.Project
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.vfs.VirtualFileManager
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Document
import com.intellij.openapi.editor.EditorFactory
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.editor.LogicalPosition
import com.intellij.openapi.editor.SelectionModel
import com.intellij.openapi.editor.event.DocumentListener
import com.intellij.openapi.editor.event.EditorMouseListener
import com.intellij.openapi.editor.event.EditorMouseEvent
import com.intellij.openapi.editor.event.CaretListener
import com.intellij.openapi.editor.event.CaretEvent
import com.intellij.openapi.editor.markup.RangeHighlighter
import com.intellij.openapi.editor.markup.TextAttributes
import com.intellij.openapi.editor.colors.EditorColors
import com.intellij.openapi.editor.colors.EditorColorsManager
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.Disposable
import com.intellij.openapi.ui.Messages
import com.intellij.diff.DiffManager
import com.intellij.diff.contents.DiffContent
import com.intellij.diff.contents.DocumentContent
import com.intellij.diff.contents.FileContent
import com.intellij.diff.requests.DiffRequest
import com.intellij.diff.requests.SimpleDiffRequest
import com.intellij.diff.util.DiffUserDataKeys
import com.intellij.diff.util.DiffUtil
import com.intellij.util.concurrency.AppExecutorUtil
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.Implementation
import io.modelcontextprotocol.kotlin.sdk.server.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Tool
import io.modelcontextprotocol.kotlin.sdk.server.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.server.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Notification
import kotlinx.coroutines.*
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Main IDE server implementation for JetBrains IDEs.
 * 
 * This service manages the MCP server, handles IDE context updates,
 * and provides tools for diff operations following the VS Code companion
 * extension patterns.
 */
@Service(Service.Level.PROJECT)
class IDEServer(
    private val project: Project
) : Disposable {
    
    private val logger = logger<IDEServer>()
    private val coroutineScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    private val transport = StreamableHttpServerTransport(
        project = project,
        enableDnsRebindingProtection = true,
        allowedHosts = setOf("localhost", "127.0.0.1", "[::1]"),
        allowedOrigins = setOf("http://localhost", "http://127.0.0.1")
    )
    
    // CORRECT: Single MCP server instance for HTTP transport
    // Handles multiple clients through session management
    private val mcpServer = Server(
        serverInfo = Implementation(
            name = "jetbrains-ide-companion",
            version = "1.0.0"
        ),
        options = ServerOptions(
            capabilities = createServerCapabilities()
        )
    )
    
    // Context tracking
    private val openFilesManager = OpenFilesManager(project)
    private val diffManager = DiffManager(project)
    private val activeDiffs = ConcurrentHashMap<String, DiffContext>()
    
    data class DiffContext(
        val filePath: String,
        val originalContent: String,
        val proposedContent: String,
        val sessionId: String,
        val createdAt: Long
    )
    
    private var discoveryFile: File? = null
    private var isStarted = false
    
    init {
        Disposer.register(project, this)
    }
    
    fun start() {
        if (isStarted) {
            logger.warn("IDEServer already started")
            return
        }
        
        logger.info("Starting JetBrains IDE Companion Server")
        
        try {
            val port = transport.start()
            createDiscoveryFile(port, transport.getAuthToken())
            registerMcpTools()
            setupContextTracking()
            
            isStarted = true
            logger.info("IDE server started successfully on port $port")
        } catch (e: Exception) {
            logger.error("Failed to start IDE server", e)
            throw e
        }
    }
    
    private fun createDiscoveryFile(port: Int, authToken: String) {
        val tmpDir = System.getProperty("java.io.tmpdir")
        val ideDir = File(tmpDir, "gemini/ide")
        ideDir.mkdirs()
        
        val pid = ProcessHandle.current().pid()
        val discoveryFile = File(ideDir, "gemini-ide-server-$pid-$port.json")
        
        val workspacePaths = listOfNotNull(project.basePath)
            .joinToString(File.pathSeparator)
        
        val discoveryData = """
        {
          "port": $port,
          "workspacePath": "$workspacePaths",
          "authToken": "$authToken",
          "ideInfo": {
            "name": "jetbrains",
            "displayName": "JetBrains IDE"
          }
        }
        """.trimIndent()
        
        try {
            discoveryFile.writeText(discoveryData)
            
            // Set secure permissions (Unix-like systems)
            if (System.getProperty("os.name").lowercase().contains("win").not()) {
                val path = discoveryFile.toPath()
                Files.setPosixFilePermissions(
                    path,
                    PosixFilePermissions.fromString("rw-------")
                )
            }
            
            this.discoveryFile = discoveryFile
            logger.info("Discovery file created: ${discoveryFile.absolutePath}")
        } catch (e: Exception) {
            logger.error("Failed to create discovery file", e)
            throw e
        }
    }
    
    private fun registerMcpTools() {
        // Register IDE-specific tools following VS Code patterns
        
        mcpServer.addTool(
            name = "openDiff",
            description = "(IDE Tool) Open a diff view to create or modify a file. Returns a notification once the diff has been accepted or rejected.",
            inputSchema = mapOf(
                "type" to "object",
                "properties" to mapOf(
                    "filePath" to mapOf("type" to "string", "description" to "The absolute path to the file to be diffed"),
                    "newContent" to mapOf("type" to "string", "description" to "The proposed new content for the file")
                ),
                "required" to listOf("filePath", "newContent")
            ),
            handler = { request ->
                val filePath = request["filePath"] as String
                val newContent = request["newContent"] as String
                
                try {
                    diffManager.showDiff(filePath, newContent)
                    CallToolResult(content = emptyList())
                } catch (e: Exception) {
                    logger.error("Failed to show diff for $filePath", e)
                    CallToolResult(
                        isError = true,
                        content = listOf(
                            TextContent(
                                type = "text",
                                text = "Failed to open diff: ${e.message}"
                            )
                        )
                    )
                }
            }
        )
        
        mcpServer.addTool(
            name = "closeDiff",
            description = "(IDE Tool) Close an open diff view for a specific file.",
            inputSchema = mapOf(
                "type" to "object",
                "properties" to mapOf(
                    "filePath" to mapOf("type" to "string", "description" to "The absolute path to the file whose diff view should be closed")
                ),
                "required" to listOf("filePath")
            ),
            handler = { request ->
                val filePath = request["filePath"] as String
                
                try {
                    val content = diffManager.closeDiff(filePath)
                    CallToolResult(
                        content = listOf(
                            TextContent(
                                type = "text",
                                text = content ?: ""
                            )
                        )
                    )
                } catch (e: Exception) {
                    logger.error("Failed to close diff for $filePath", e)
                    CallToolResult(
                        isError = true,
                        content = listOf(
                            TextContent(
                                type = "text",
                                text = "Failed to close diff: ${e.message}"
                            )
                        )
                    )
                }
            }
        )
        
        mcpServer.addTool(
            name = "getActiveFile",
            description = "Returns the path of the currently active file",
            inputSchema = mapOf("type" to "object", "properties" to emptyMap<String, Any>()),
            handler = { _ ->
                val activeFile = getActiveFilePath()
                CallToolResult(
                    content = listOf(
                        TextContent(
                            type = "text",
                            text = activeFile ?: ""
                        )
                    )
                )
            }
        )
        
        logger.info("MCP tools registered successfully")
    }
    
    private fun setupContextTracking() {
        // Set up listeners for IDE context changes
        openFilesManager.onDidChange { context ->
            broadcastIdeContextUpdate(context)
        }
        
        diffManager.onDidChange { notification ->
            broadcastDiffNotification(notification)
        }
    }
    
    private fun broadcastIdeContextUpdate(context: IdeContext) {
        val notification = Notification(
            jsonrpc = "2.0",
            method = "ide/contextUpdate",
            params = context
        )
        
        // Send to all active sessions
        transport.getActiveSessions().keys.forEach { sessionId ->
            try {
                // Implementation would send notification to specific session
                logger.debug("Broadcasting context update to session: $sessionId")
            } catch (e: Exception) {
                logger.warn("Failed to send context update to session $sessionId", e)
            }
        }
    }
    
    private fun broadcastDiffNotification(notification: Notification) {
        // Send diff notifications to relevant sessions
        logger.debug("Broadcasting diff notification: ${notification.method}")
    }
    
    private fun getActiveFilePath(): String? {
        return ReadAction.compute<String?, Exception> {
            val fileEditorManager = FileEditorManager.getInstance(project)
            val selectedFiles = fileEditorManager.selectedFiles
            
            if (selectedFiles.isNotEmpty()) {
                selectedFiles[0].path
            } else {
                null
            }
        }
    }
    
    private fun createServerCapabilities() = ServerCapabilities(
        resources = ServerCapabilities.Resources(
            subscribe = true,
            listChanged = true
        ),
        tools = ServerCapabilities.Tools(
            listChanged = true
        ),
        logging = ServerCapabilities.Logging()
    )
    
    fun getPort(): Int = transport.getPort()
    
    fun getAuthToken(): String = transport.getAuthToken()
    
    fun getActiveSessions(): Map<String, StreamableHttpServerTransport.SessionContext> {
        return transport.getActiveSessions()
    }
    
    override fun dispose() {
        logger.info("Disposing IDEServer")
        
        coroutineScope.cancel()
        
        if (isStarted) {
            try {
                transport.dispose()
                
                discoveryFile?.let { file ->
                    try {
                        if (file.exists()) {
                            file.delete()
                            logger.info("Discovery file deleted: ${file.absolutePath}")
                        }
                    } catch (e: Exception) {
                        logger.warn("Failed to delete discovery file", e)
                    }
                }
                
                isStarted = false
                logger.info("IDE server disposed successfully")
            } catch (e: Exception) {
                logger.error("Error during IDE server disposal", e)
            }
        }
    }
}

// Data classes for IDE context
data class IdeContext(
    val workspaceState: WorkspaceState? = null
)

data class WorkspaceState(
    val openFiles: List<FileInfo>? = null,
    val isTrusted: Boolean? = null
)

data class FileInfo(
    val path: String,
    val timestamp: Long,
    val isActive: Boolean? = null,
    val cursor: CursorInfo? = null,
    val selectedText: String? = null
)

data class CursorInfo(
    val line: Int,
    val character: Int
)
