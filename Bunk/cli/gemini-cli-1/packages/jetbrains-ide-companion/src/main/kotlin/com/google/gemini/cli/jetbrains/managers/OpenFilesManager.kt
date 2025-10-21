/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

package com.google.gemini.cli.jetbrains.managers

import com.intellij.openapi.project.Project
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.FileEditorManagerListener
import com.intellij.openapi.fileEditor.FileEditorManagerEvent
import com.intellij.openapi.fileEditor.FileEditorManagerListener.FILE_EDITOR_MANAGER
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.editor.EditorFactory
import com.intellij.openapi.editor.event.EditorFactoryListener
import com.intellij.openapi.editor.event.CaretListener
import com.intellij.openapi.editor.event.CaretEvent
import com.intellij.openapi.editor.event.SelectionListener
import com.intellij.openapi.editor.event.SelectionEvent
import com.intellij.openapi.editor.SelectionModel
import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.Disposable
import com.intellij.util.concurrency.AppExecutorUtil
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.*

/**
 * Manages tracking of open files and their context in the IDE.
 * 
 * This class monitors file open/close events, cursor position changes,
 * and text selections to provide real-time context to the Gemini CLI.
 */
class OpenFilesManager(
    private val project: Project
) : Disposable {
    
    private val logger = logger<OpenFilesManager>()
    
    // Track open files with their context
    private val openFiles = ConcurrentHashMap<String, FileContext>()
    private val activeFileTimestamp = AtomicLong(System.currentTimeMillis())
    
    // Listeners
    private val fileEditorManager = FileEditorManager.getInstance(project)
    private val editorFactory = EditorFactory.getInstance()
    
    // Callbacks
    private val contextChangeCallbacks = mutableListOf<(IdeContext) -> Unit>()
    
    data class FileContext(
        val path: String,
        val timestamp: Long,
        val isActive: Boolean = false,
        val cursor: CursorInfo? = null,
        val selectedText: String? = null
    )
    
    data class CursorInfo(
        val line: Int,
        val character: Int
    )
    
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
    
    init {
        setupListeners()
    }
    
    private fun setupListeners() {
        // Listen for file editor changes
        project.messageBus.connect(this).subscribe(
            FILE_EDITOR_MANAGER,
            object : FileEditorManagerListener {
                override fun fileOpened(source: FileEditorManager, file: VirtualFile) {
                    handleFileOpened(file)
                }
                
                override fun fileClosed(source: FileEditorManager, file: VirtualFile) {
                    handleFileClosed(file)
                }
                
                override fun selectionChanged(event: FileEditorManagerEvent) {
                    handleSelectionChanged(event)
                }
            }
        )
        
        // Listen for editor creation/destruction
        editorFactory.addEditorFactoryListener(
            object : EditorFactoryListener {
                override fun editorCreated(event: EditorFactoryListener.EditorFactoryEvent) {
                    setupEditorListeners(event.editor)
                }
                
                override fun editorReleased(event: EditorFactoryListener.EditorFactoryEvent) {
                    // Editor cleanup is handled by the editor itself
                }
            },
            this
        )
    }
    
    private fun setupEditorListeners(editor: Editor) {
        // Listen for caret position changes
        editor.caretModel.addCaretListener(
            object : CaretListener {
                override fun caretPositionChanged(event: CaretEvent) {
                    handleCaretPositionChanged(editor, event)
                }
            },
            this
        )
        
        // Listen for selection changes
        editor.selectionModel.addSelectionListener(
            object : SelectionListener {
                override fun selectionChanged(event: SelectionEvent) {
                    handleSelectionChanged(editor, event)
                }
            },
            this
        )
    }
    
    private fun handleFileOpened(file: VirtualFile) {
        if (!file.isValid || file.isDirectory) return
        
        val filePath = file.path
        val timestamp = System.currentTimeMillis()
        
        openFiles[filePath] = FileContext(
            path = filePath,
            timestamp = timestamp,
            isActive = false
        )
        
        logger.debug("File opened: $filePath")
        notifyContextChanged()
    }
    
    private fun handleFileClosed(file: VirtualFile) {
        if (!file.isValid || file.isDirectory) return
        
        val filePath = file.path
        openFiles.remove(filePath)
        
        logger.debug("File closed: $filePath")
        notifyContextChanged()
    }
    
    private fun handleSelectionChanged(event: FileEditorManagerEvent) {
        val file = event.newFile
        if (file != null && file.isValid && !file.isDirectory) {
            updateActiveFile(file)
        }
    }
    
    private fun handleCaretPositionChanged(editor: Editor, event: CaretEvent) {
        val file = getFileForEditor(editor)
        if (file != null && file.isValid && !file.isDirectory) {
            updateActiveFile(file)
            updateCursorPosition(editor, file)
        }
    }
    
    private fun handleSelectionChanged(editor: Editor, event: SelectionEvent) {
        val file = getFileForEditor(editor)
        if (file != null && file.isValid && !file.isDirectory) {
            updateActiveFile(file)
            updateSelection(editor, file)
        }
    }
    
    private fun updateActiveFile(file: VirtualFile) {
        val filePath = file.path
        val timestamp = System.currentTimeMillis()
        activeFileTimestamp.set(timestamp)
        
        // Mark all files as inactive first
        openFiles.values.forEach { context ->
            if (context.isActive) {
                openFiles[context.path] = context.copy(isActive = false)
            }
        }
        
        // Mark current file as active
        val currentContext = openFiles[filePath]
        if (currentContext != null) {
            openFiles[filePath] = currentContext.copy(
                timestamp = timestamp,
                isActive = true
            )
        } else {
            openFiles[filePath] = FileContext(
                path = filePath,
                timestamp = timestamp,
                isActive = true
            )
        }
        
        notifyContextChanged()
    }
    
    private fun updateCursorPosition(editor: Editor, file: VirtualFile) {
        val filePath = file.path
        val currentContext = openFiles[filePath] ?: return
        
        val caretModel = editor.caretModel
        val logicalPosition = caretModel.logicalPosition
        
        val cursorInfo = CursorInfo(
            line = logicalPosition.line + 1, // Convert to 1-based
            character = logicalPosition.column + 1 // Convert to 1-based
        )
        
        openFiles[filePath] = currentContext.copy(cursor = cursorInfo)
        notifyContextChanged()
    }
    
    private fun updateSelection(editor: Editor, file: VirtualFile) {
        val filePath = file.path
        val currentContext = openFiles[filePath] ?: return
        
        val selectionModel = editor.selectionModel
        val selectedText = if (selectionModel.hasSelection()) {
            val text = selectionModel.selectedText
            // Limit selection to 16KB as per VS Code implementation
            if (text != null && text.length > 16384) {
                text.substring(0, 16384)
            } else {
                text
            }
        } else {
            null
        }
        
        openFiles[filePath] = currentContext.copy(selectedText = selectedText)
        notifyContextChanged()
    }
    
    private fun getFileForEditor(editor: Editor): VirtualFile? {
        return ReadAction.compute<VirtualFile?, Exception> {
            val document = editor.document
            val virtualFile = com.intellij.openapi.fileEditor.FileDocumentManager.getInstance()
                .getFile(document)
            virtualFile
        }
    }
    
    private fun notifyContextChanged() {
        val context = buildIdeContext()
        
        // Notify all registered callbacks
        contextChangeCallbacks.forEach { callback ->
            try {
                callback(context)
            } catch (e: Exception) {
                logger.warn("Error in context change callback", e)
            }
        }
    }
    
    private fun buildIdeContext(): IdeContext {
        val fileInfos = openFiles.values
            .sortedByDescending { it.timestamp }
            .take(10) // Limit to 10 most recent files
            .map { context ->
                FileInfo(
                    path = context.path,
                    timestamp = context.timestamp,
                    isActive = context.isActive,
                    cursor = context.cursor,
                    selectedText = context.selectedText
                )
            }
        
        return IdeContext(
            workspaceState = WorkspaceState(
                openFiles = fileInfos,
                isTrusted = true // JetBrains projects are typically trusted
            )
        )
    }
    
    fun onDidChange(callback: (IdeContext) -> Unit) {
        contextChangeCallbacks.add(callback)
    }
    
    fun removeCallback(callback: (IdeContext) -> Unit) {
        contextChangeCallbacks.remove(callback)
    }
    
    val state: IdeContext
        get() = buildIdeContext()
    
    override fun dispose() {
        logger.info("Disposing OpenFilesManager")
        contextChangeCallbacks.clear()
        openFiles.clear()
    }
}
