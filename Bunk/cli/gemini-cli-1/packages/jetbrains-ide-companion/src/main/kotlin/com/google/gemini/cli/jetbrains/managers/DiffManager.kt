/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

package com.google.gemini.cli.jetbrains.managers

import com.intellij.openapi.project.Project
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.Disposable
import com.intellij.diff.DiffManager
import com.intellij.diff.contents.DocumentContent
import com.intellij.diff.contents.FileContent
import com.intellij.diff.requests.SimpleDiffRequest
import com.intellij.diff.util.DiffUserDataKeys
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.editor.Document
import com.intellij.openapi.vfs.VirtualFileManager
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.command.WriteCommandAction
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages diff operations for the IDE companion.
 * 
 * This class handles opening diff views, tracking diff state,
 * and notifying about diff acceptance/rejection.
 */
class DiffManager(
    private val project: Project
) : Disposable {
    
    private val logger = logger<DiffManager>()
    private val activeDiffs = ConcurrentHashMap<String, DiffContext>()
    private val diffChangeCallbacks = mutableListOf<(DiffNotification) -> Unit>()
    
    data class DiffContext(
        val filePath: String,
        val originalContent: String,
        val proposedContent: String,
        val sessionId: String,
        val createdAt: Long
    )
    
    data class DiffNotification(
        val type: String, // "accepted" or "rejected"
        val filePath: String,
        val content: String? = null
    )
    
    fun showDiff(filePath: String, newContent: String) {
        try {
            val file = VirtualFileManager.getInstance().findFileByNioPath(File(filePath).toPath())
            if (file == null) {
                throw IllegalArgumentException("File not found: $filePath")
            }
            
            val document = FileDocumentManager.getInstance().getDocument(file)
            val originalContent = document?.text ?: ""
            
            // Create diff content
            val originalContentObj = FileContent(project, file)
            val proposedContentObj = DocumentContent(
                project,
                FileDocumentManager.getInstance().getDocument(file) ?: return,
                file.name
            )
            
            // Create diff request
            val diffRequest = SimpleDiffRequest(
                "Gemini CLI Diff: ${file.name}",
                originalContentObj,
                proposedContentObj,
                "Original",
                "Proposed"
            )
            
            // Set up diff data for tracking
            diffRequest.putUserData(DiffUserDataKeys.CONTEXT_ACTIONS, listOf())
            
            // Store diff context
            val sessionId = java.util.UUID.randomUUID().toString()
            activeDiffs[filePath] = DiffContext(
                filePath = filePath,
                originalContent = originalContent,
                proposedContent = newContent,
                sessionId = sessionId,
                createdAt = System.currentTimeMillis()
            )
            
            // Show diff
            DiffManager.getInstance().showDiff(project, diffRequest)
            
            logger.info("Diff shown for file: $filePath")
            
        } catch (e: Exception) {
            logger.error("Failed to show diff for $filePath", e)
            throw e
        }
    }
    
    fun closeDiff(filePath: String): String? {
        val diffContext = activeDiffs.remove(filePath)
        if (diffContext != null) {
            logger.info("Diff closed for file: $filePath")
            return diffContext.originalContent
        }
        return null
    }
    
    fun onDidChange(callback: (DiffNotification) -> Unit) {
        diffChangeCallbacks.add(callback)
    }
    
    fun removeCallback(callback: (DiffNotification) -> Unit) {
        diffChangeCallbacks.remove(callback)
    }
    
    private fun notifyDiffChanged(notification: DiffNotification) {
        diffChangeCallbacks.forEach { callback ->
            try {
                callback(notification)
            } catch (e: Exception) {
                logger.warn("Error in diff change callback", e)
            }
        }
    }
    
    override fun dispose() {
        logger.info("Disposing DiffManager")
        activeDiffs.clear()
        diffChangeCallbacks.clear()
    }
}
