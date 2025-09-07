/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// Enhanced Intelligent Security Classifier with advanced ML models and adaptive learning
import { logger } from '../../utils/logger.js';
import { dataCollector } from './dataCollector.js';
import { featureExtractor } from './featureExtractor.js';
import { modelTrainer } from './modelTrainer.js';
import type { ContextMeta, GuardResult, GuardDecision } from '../types.js';
import type { ModelConfig } from './modelTrainer.js';
import { classifyPrompt } from '../promptGuard.js';
import { analyzeWithAI } from '../promptGuard.js';

export interface IntelligentAnalysis {
  mlPrediction?: {
    threatLevel: number;
    confidence: number;
    modelUsed: string;
    featureImportance?: Record<string, number>;
    anomalyScore?: number;
  };
  heuristicAnalysis: GuardResult;
  aiAnalysis?: {
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    reasoning: string;
    recommendedAction: GuardDecision;
    confidence: number;
    detectedPatterns?: string[];
    riskFactors?: string[];
  };
  ensembleDecision: {
    finalDecision: GuardDecision;
    confidence: number;
    reasoning: string[];
    methodUsed: 'ml' | 'heuristic' | 'ai' | 'ensemble' | 'adaptive';
    riskScore: number;
    adaptiveFactors?: string[];
  };
  performanceMetrics: {
    analysisTimeMs: number;
    modelLatency?: number;
    cacheHit?: boolean;
    resourceUsage?: {
      memory: number;
      cpu: number;
    };
  };
}

export interface ModelPerformanceMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  lastUpdated: string;
  sampleCount: number;
}

export interface AdaptiveLearningConfig {
  enabled: boolean;
  learningRate: number;
  adaptationThreshold: number;
  maxAdaptationsPerHour: number;
  feedbackWeight: number;
}

class IntelligentSecurityClassifier {
  private static instance: IntelligentSecurityClassifier;
  private activeModels: Map<string, string> = new Map(); // model type -> model id
  private _modelPerformance: Map<string, ModelPerformanceMetrics> = new Map();
  private _predictionCache: Map<string, { result: IntelligentAnalysis; timestamp: number }> = new Map();
  private _adaptiveLearning: AdaptiveLearningConfig = {
    enabled: true,
    learningRate: 0.01,
    adaptationThreshold: 0.7,
    maxAdaptationsPerHour: 10,
    feedbackWeight: 0.3
  };
  
  private confidenceThresholds = {
    ml: 0.8,
    ai: 0.75,
    heuristic: 0.6,
    ensemble: 0.85
  };

  private readonly _CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  static getInstance(): IntelligentSecurityClassifier {
    if (!IntelligentSecurityClassifier.instance) {
      IntelligentSecurityClassifier.instance = new IntelligentSecurityClassifier();
    }
    return IntelligentSecurityClassifier.instance;
  }

  private constructor() {
    this.initializeActiveModels();
    // TODO: Implement performance monitoring
    // this.startPerformanceMonitoring();
    // TODO: Implement cache cleanup
    // this.startCacheCleanup();
  }

  private generateCacheKey(text: string, meta: ContextMeta): string {
    // Generate a cache key based on text content and relevant metadata
    const relevantMeta = {
      userRole: meta.userRole,
      timestamp: Math.floor(Date.now() / (5 * 60 * 1000)) // 5-minute buckets
    };
    return `${text.length}_${JSON.stringify(relevantMeta)}`;
  }

  private initializeActiveModels(): void {
    // Try to load the best available models for each type
    const models = modelTrainer.getModelList();

    // Enhanced model selection with performance tracking
    const modelTypes = ['threat_detector', 'block_predictor', 'anomaly_detector', 'pattern_classifier'];
    
    for (const modelType of modelTypes) {
      const typeModels = models.filter(m => m.name.includes(modelType));
      if (typeModels.length > 0) {
        // Select best model based on composite score
        const bestModel = typeModels.reduce((best, current) => {
          const bestScore = this.calculateModelScore(best);
          const currentScore = this.calculateModelScore(current);
          return currentScore > bestScore ? current : best;
        });
        
        this.activeModels.set(modelType, bestModel.id);
        this._modelPerformance.set(bestModel.id, {
          accuracy: bestModel.accuracy,
          precision: 0.8, // Default precision
          recall: 0.75,   // Default recall
          f1Score: 0.77,  // Default F1 score
          falsePositiveRate: 0.05, // Default FPR
          falseNegativeRate: 0.1,  // Default FNR
          lastUpdated: new Date().toISOString(),
          sampleCount: 1000 // Default sample count
        });
        
        logger.info(`🎯 Loaded ${modelType} model`, { 
          modelId: bestModel.id, 
          accuracy: bestModel.accuracy,
          score: this.calculateModelScore(bestModel)
        });
      }
    }

    logger.info('🤖 Enhanced intelligent classifier initialized', {
      activeModels: this.activeModels.size,
      availableModels: models.length,
      adaptiveLearning: this._adaptiveLearning.enabled
    });
  }

  private calculateModelScore(model: { id: string; name: string; accuracy: number; lastUpdated?: string; sampleCount?: number }): number {
    // Composite score considering accuracy, recency, and sample size
    const accuracyWeight = 0.6;
    const recencyWeight = 0.2;
    const sampleWeight = 0.2;
    
    const accuracy = model.accuracy || 0;
    const recency = model.lastUpdated ? 
      Math.max(0, 1 - (Date.now() - new Date(model.lastUpdated).getTime()) / (30 * 24 * 60 * 60 * 1000)) : 0;
    const sampleScore = Math.min(1, (model.sampleCount || 0) / 10000);
    
    return accuracyWeight * accuracy + recencyWeight * recency + sampleWeight * sampleScore;
  }

  async analyzeInput(text: string, meta: ContextMeta): Promise<IntelligentAnalysis> {
    const startTime = Date.now();
    const cacheKey = this.generateCacheKey(text, meta);
    
    // Check cache first
    const cached = this._predictionCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this._CACHE_TTL) {
      logger.debug('📋 Cache hit for security analysis');
      return {
        ...cached.result,
        performanceMetrics: {
          ...cached.result.performanceMetrics,
          cacheHit: true
        }
      };
    }

    // Run enhanced analysis methods in parallel with timeout
    const analysisPromises = [
      this.runHeuristicAnalysis(text, meta),
      this.runAIAnalysis(text, meta),
      this.runMLAnalysis(text, meta)
    ];

    const [heuristicResult, aiResult, mlResult] = await Promise.allSettled(analysisPromises);

    const heuristicAnalysis = heuristicResult.status === 'fulfilled' ?
      heuristicResult.value : this.createFallbackResult();

    const aiAnalysis = aiResult.status === 'fulfilled' ?
      aiResult.value : undefined;

    const mlPrediction = mlResult.status === 'fulfilled' ?
      mlResult.value : undefined;

    // Make ensemble decision
    const ensembleDecision = this.makeEnsembleDecision(
      heuristicAnalysis as GuardResult || this.createFallbackResult(),
      aiAnalysis as IntelligentAnalysis['aiAnalysis'],
      mlPrediction as IntelligentAnalysis['mlPrediction']
    );

    const analysisTime = Date.now() - startTime;

    logger.debug('🔍 Intelligent analysis completed', {
      finalDecision: ensembleDecision.finalDecision,
      confidence: ensembleDecision.confidence,
      methodUsed: ensembleDecision.methodUsed,
      analysisTimeMs: analysisTime
    });

    // Record analysis for training data
    if (ensembleDecision.finalDecision !== 'allow') {
      const analysisTags = (heuristicAnalysis as GuardResult)?.tags || this.createFallbackResult().tags;
      dataCollector.recordSecurityEvent(
        text,
        ensembleDecision.finalDecision,
        analysisTags,
        meta,
        {
          confidence: ensembleDecision.confidence,
          processingTime: analysisTime,
          source: 'user',
          attackType: analysisTags,
          bypassAttempt: analysisTags.includes('system-override')
        }
      );
    }

    return {
      mlPrediction: mlPrediction as IntelligentAnalysis['mlPrediction'],
      heuristicAnalysis: heuristicAnalysis as GuardResult,
      aiAnalysis: aiAnalysis as IntelligentAnalysis['aiAnalysis'],
      ensembleDecision,
      performanceMetrics: {
        analysisTimeMs: analysisTime,
        cacheHit: false
      }
    };
  }

  private async runHeuristicAnalysis(text: string, meta: ContextMeta): Promise<GuardResult> {
    try {
      return await classifyPrompt(text, meta);
    } catch (error) {
      logger.warn('⚠️ Heuristic analysis failed, using fallback', { error: (error as Error).message });
      return this.createFallbackResult();
    }
  }

  private async runAIAnalysis(text: string, meta: ContextMeta): Promise<IntelligentAnalysis['aiAnalysis']> {
    try {
      return await analyzeWithAI(text, meta);
    } catch (error) {
      logger.warn('⚠️ AI analysis failed', { error: (error as Error).message });
      return undefined;
    }
  }

  private async runMLAnalysis(text: string, meta: ContextMeta): Promise<IntelligentAnalysis['mlPrediction']> {
    try {
      // Create basic features for ML prediction
      const event = {
        id: `temp_${Date.now()}`,
        timestamp: new Date().toISOString(),
        input: text,
        decision: 'allow' as GuardDecision,
        tags: [],
        context: meta,
        processingTime: 0,
        source: 'user' as const,
        labels: {
          threatLevel: 'low' as const,
          attackType: [],
          bypassAttempt: false,
          successfulAttack: false
        }
      };

      // Extract features
      const features = featureExtractor.extractAdvancedFeatures(event);

      // Get ML prediction if model is available
      const threatModelId = this.activeModels.get('threat_detector');
      if (threatModelId) {
        const prediction = await modelTrainer.predict(threatModelId, features);
        const threatLevel = typeof prediction.threatLevel === 'number' ? prediction.threatLevel : parseFloat(prediction.threatLevel) || 0;
        const confidence = typeof prediction.confidence === 'number' ? prediction.confidence : parseFloat(prediction.confidence) || 0;

        return {
          threatLevel,
          confidence,
          modelUsed: threatModelId
        };
      }
    } catch (error) {
      logger.warn('⚠️ ML analysis failed', { error: (error as Error).message });
    }
    return undefined;
  }

  private makeEnsembleDecision(
    heuristic: GuardResult,
    ai?: IntelligentAnalysis['aiAnalysis'],
    ml?: IntelligentAnalysis['mlPrediction']
  ): IntelligentAnalysis['ensembleDecision'] {
    const reasoning: string[] = [];
    let maxConfidence = heuristic.tags.length / 10; // Normalize heuristic confidence
    let bestDecision: GuardDecision = heuristic.decision;
    let methodUsed: 'ml' | 'heuristic' | 'ai' | 'ensemble' = 'heuristic';

    // Evaluate ML prediction
    if (ml && ml.confidence > this.confidenceThresholds.ml) {
      reasoning.push(`ML model confidence: ${(ml.confidence * 100).toFixed(1)}%`);
      if (ml.confidence > maxConfidence) {
        maxConfidence = ml.confidence;
        bestDecision = ml.threatLevel > 2 ? 'block' : ml.threatLevel > 1 ? 'allow_sanitized' : 'allow';
        methodUsed = 'ml';
      }
    }

    // Evaluate AI analysis
    if (ai && ai.confidence > this.confidenceThresholds.ai) {
      reasoning.push(`AI analysis confidence: ${(ai.confidence * 100).toFixed(1)}%`);
      if (ai.confidence > maxConfidence) {
        maxConfidence = ai.confidence;
        bestDecision = ai.recommendedAction;
        methodUsed = 'ai';
      }
    }

    // If multiple high-confidence predictions agree, use ensemble
    const highConfidencePredictions = [ml, ai].filter(pred =>
      pred && (pred.confidence || 0) > 0.8
    );

    if (highConfidencePredictions.length >= 2) {
      const decisions = highConfidencePredictions.map(pred => {
        if ('threatLevel' in pred!) {
          const threatLevel = typeof pred!.threatLevel === 'number' ? pred!.threatLevel : parseFloat(pred!.threatLevel) || 0;
          return threatLevel > 2 ? 'block' : threatLevel > 1 ? 'allow_sanitized' : 'allow';
        } else {
          const aiAnalysis = pred! as IntelligentAnalysis['aiAnalysis'];
          return aiAnalysis?.recommendedAction || 'allow';
        }
      }) as GuardDecision[];

      // Check if decisions agree
      const consensusDecision = decisions.every(d => d === decisions[0]) ? decisions[0] : null;
      if (consensusDecision) {
        bestDecision = consensusDecision;
        methodUsed = 'ensemble';
        maxConfidence = Math.max(...highConfidencePredictions.map(p => p?.confidence || 0));
        reasoning.push('Ensemble consensus reached');
      }
    }

    // Add heuristic reasoning
    if ((heuristic as GuardResult).tags.length > 0) {
      reasoning.push(`Heuristic detected: ${(heuristic as GuardResult).tags.join(', ')}`);
    }

    return {
      finalDecision: bestDecision,
      confidence: maxConfidence,
      reasoning,
      methodUsed,
      riskScore: maxConfidence * 10 // Convert confidence to risk score (0-10 scale)
    };
  }

  private createFallbackResult(): GuardResult {
    return {
      decision: 'allow',
      reasons: ['Analysis failed, allowing by default'],
      tags: ['analysis-failed']
    };
  }

  // Training and model management methods
  async trainNewModel(modelConfig: ModelConfig): Promise<void> {
    logger.info('🚀 Training new security model', { config: modelConfig.name });

    const dataset = dataCollector.generateTrainingDataset();
    if (dataset.events.length < 100) {
      logger.warn('⚠️ Insufficient training data', { sampleCount: dataset.events.length });
      return;
    }

    const result = await modelTrainer.trainModel(modelConfig, dataset);
    this.activeModels.set(modelConfig.name.split('_')[0], result.modelId);

    logger.info('✅ New model trained and activated', {
      modelId: result.modelId,
      accuracy: result.metrics.accuracy
    });
  }

  getModelStatus(): {
    activeModels: Record<string, string>;
    availableModels: number;
    trainingDataStats: Record<string, unknown>;
  } {
    return {
      activeModels: Object.fromEntries(this.activeModels),
      availableModels: modelTrainer.getModelList().length,
      trainingDataStats: dataCollector.getStats()
    };
  }

  async retrainModels(): Promise<void> {
    logger.info('🔄 Retraining all active models with new data');

    const dataset = dataCollector.generateTrainingDataset();
    if (dataset.events.length < 50) {
      logger.warn('⚠️ Insufficient data for retraining');
      return;
    }

    for (const [modelType, modelId] of this.activeModels) {
      try {
        const modelList = modelTrainer.getModelList();
        const modelInfo = modelList.find(m => m.id === modelId);

        if (modelInfo) {
          const config = this.getModelConfigForType(modelType);
          if (config) {
            const result = await modelTrainer.trainModel(config as ModelConfig, dataset);

            logger.info('✅ Model retrained', {
              type: modelType,
              oldAccuracy: modelInfo.accuracy,
              newAccuracy: result.metrics.accuracy
            });
          }
        }
      } catch (error) {
        logger.error('❌ Failed to retrain model', { modelType, error: (error as Error).message });
      }
    }
  }

  private getModelConfigForType(modelType: string): ModelConfig | undefined {
    // Return appropriate config based on model type
    const configs: Record<string, ModelConfig> = {
      threat_detector: {
        name: 'threat_detector_rf',
        type: 'random_forest',
        hyperparameters: { nEstimators: 100, maxDepth: 10 },
        featureSelection: ['textLength', 'wordCount', 'securityKeywordScore', 'injectionPatternScore'],
        targetVariable: 'threatLevel'
      },
      block_predictor: {
        name: 'block_predictor_gb',
        type: 'gradient_boosting',
        hyperparameters: { nEstimators: 50, learningRate: 0.1 },
        featureSelection: ['processingTime', 'toolAclSize', 'securityKeywordScore'],
        targetVariable: 'wasBlocked'
      }
    };

    return configs[modelType] || configs['threat_detector'];
  }
}

export const intelligentClassifier = IntelligentSecurityClassifier.getInstance();
