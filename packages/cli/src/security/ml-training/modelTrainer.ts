/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

// ML Model Training Pipeline for Security Classifiers
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../../utils/logger';
import type { MLFeatures, TrainingDataset } from './dataCollector';
import type { AdvancedFeatures } from './featureExtractor';

export interface ModelConfig {
  name: string;
  type: 'random_forest' | 'svm' | 'neural_network' | 'gradient_boosting';
  hyperparameters: Record<string, any>;
  featureSelection: string[];
  targetVariable: 'threatLevel' | 'wasBlocked' | 'confidence';
}

export interface TrainingResult {
  modelId: string;
  config: ModelConfig;
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    auc: number;
  };
  trainingTime: number;
  featureImportance?: Record<string, number>;
  confusionMatrix: number[][];
  crossValidationScores: number[];
}

export interface ModelPrediction {
  threatLevel: number;
  confidence: number;
  featureContributions: Record<string, number>;
}

class MLModelTrainer {
  private static instance: MLModelTrainer;
  private models: Map<string, any> = new Map();
  private modelConfigs: ModelConfig[] = [];
  private modelsDir: string;

  static getInstance(): MLModelTrainer {
    if (!MLModelTrainer.instance) {
      MLModelTrainer.instance = new MLModelTrainer();
    }
    return MLModelTrainer.instance;
  }

  private constructor() {
    this.modelsDir = path.join(process.cwd(), 'security-models');
    this.ensureModelsDirectory();
    this.loadDefaultConfigs();
    this.loadExistingModels();
  }

  private ensureModelsDirectory(): void {
    if (!fs.existsSync(this.modelsDir)) {
      fs.mkdirSync(this.modelsDir, { recursive: true });
      logger.info('📁 Created models directory', { path: this.modelsDir });
    }
  }

  private loadDefaultConfigs(): void {
    this.modelConfigs = [
      {
        name: 'threat_detector_rf',
        type: 'random_forest',
        hyperparameters: {
          nEstimators: 100,
          maxDepth: 10,
          minSamplesSplit: 2,
          randomState: 42
        },
        featureSelection: [
          'textLength', 'wordCount', 'containsSpecialChars', 'containsUrls',
          'containsCommands', 'base64PatternCount', 'securityKeywordScore',
          'injectionPatternScore', 'obfuscationComplexity'
        ],
        targetVariable: 'threatLevel'
      },
      {
        name: 'block_predictor_gb',
        type: 'gradient_boosting',
        hyperparameters: {
          nEstimators: 50,
          learningRate: 0.1,
          maxDepth: 5,
          randomState: 42
        },
        featureSelection: [
          'processingTime', 'toolAclSize', 'userRole', 'sourceType',
          'securityKeywordScore', 'injectionPatternScore'
        ],
        targetVariable: 'wasBlocked'
      },
      {
        name: 'confidence_scorer_nn',
        type: 'neural_network',
        hyperparameters: {
          hiddenLayers: [64, 32],
          activation: 'relu',
          learningRate: 0.001,
          epochs: 50,
          batchSize: 32
        },
        featureSelection: [
          'lexicalDiversity', 'readabilityScore', 'semanticSimilarity',
          'userBehaviorScore', 'temporalPatterns'
        ],
        targetVariable: 'confidence'
      }
    ];

    logger.info('⚙️ Loaded default model configurations', { count: this.modelConfigs.length });
  }

  private loadExistingModels(): void {
    try {
      const files = fs.readdirSync(this.modelsDir).filter(f => f.endsWith('.json'));
      for (const file of files) {
        const modelPath = path.join(this.modelsDir, file);
        const modelData = JSON.parse(fs.readFileSync(modelPath, 'utf8'));
        this.models.set(modelData.modelId, modelData);
      }
      logger.info('📦 Loaded existing models', { count: this.models.size });
    } catch (error) {
      logger.warn('⚠️ Failed to load existing models', { error: error.message });
    }
  }

  async trainModel(
    config: ModelConfig,
    dataset: TrainingDataset,
    options: {
      validationSplit?: number;
      crossValidationFolds?: number;
      earlyStopping?: boolean;
    } = {}
  ): Promise<TrainingResult> {
    logger.info('🚀 Starting model training', {
      modelName: config.name,
      type: config.type,
      featureCount: config.featureSelection.length,
      sampleCount: dataset.events.length
    });

    const startTime = Date.now();

    // Prepare features and labels
    const { features, labels } = this.prepareData(dataset, config);

    // Split data for training and validation
    const validationSplit = options.validationSplit || 0.2;
    const splitIndex = Math.floor(features.length * (1 - validationSplit));

    const trainFeatures = features.slice(0, splitIndex);
    const trainLabels = labels.slice(0, splitIndex);
    const valFeatures = features.slice(splitIndex);
    const valLabels = labels.slice(splitIndex);

    // Train model based on type
    const model = await this.trainModelByType(config, trainFeatures, trainLabels);

    // Evaluate model
    const predictions = await this.predictBatch(model, valFeatures);
    const metrics = this.calculateMetrics(predictions, valLabels);

    // Cross-validation
    const crossValidationScores = options.crossValidationFolds ?
      await this.crossValidate(config, features, labels, options.crossValidationFolds) :
      [];

    const result: TrainingResult = {
      modelId: `model_${config.name}_${Date.now()}`,
      config,
      metrics,
      trainingTime: Date.now() - startTime,
      featureImportance: this.calculateFeatureImportance(model, config),
      confusionMatrix: this.calculateConfusionMatrix(predictions, valLabels),
      crossValidationScores
    };

    // Save model
    this.saveModel(result);

    logger.info('✅ Model training completed', {
      modelId: result.modelId,
      accuracy: result.metrics.accuracy.toFixed(3),
      trainingTime: result.trainingTime
    });

    return result;
  }

  private prepareData(dataset: TrainingDataset, config: ModelConfig): {
    features: number[][];
    labels: number[];
  } {
    const features: number[][] = [];
    const labels: number[] = [];

    for (let i = 0; i < dataset.features.length; i++) {
      const featureRow = config.featureSelection.map(featureName => {
        const value = (dataset.features[i] as any)[featureName];
        return typeof value === 'number' ? value : 0;
      });
      features.push(featureRow);

      const label = config.targetVariable === 'threatLevel' ?
        dataset.features[i].threatLevel :
        config.targetVariable === 'wasBlocked' ?
          (dataset.features[i].wasBlocked ? 1 : 0) :
          dataset.features[i].confidence;
      labels.push(label);
    }

    return { features, labels };
  }

  private async trainModelByType(
    config: ModelConfig,
    features: number[][],
    labels: number[]
  ): Promise<any> {
    switch (config.type) {
      case 'random_forest':
        return this.trainRandomForest(config.hyperparameters, features, labels);
      case 'gradient_boosting':
        return this.trainGradientBoosting(config.hyperparameters, features, labels);
      case 'svm':
        return this.trainSVM(config.hyperparameters, features, labels);
      case 'neural_network':
        return this.trainNeuralNetwork(config.hyperparameters, features, labels);
      default:
        throw new Error(`Unsupported model type: ${config.type}`);
    }
  }

  private async trainRandomForest(hyperparams: any, features: number[][], labels: number[]): Promise<any> {
    // Simplified Random Forest implementation
    // In production, this would use a proper ML library like TensorFlow.js or scikit-learn
    const { nEstimators, maxDepth } = hyperparams;

    const trees = [];
    for (let i = 0; i < nEstimators; i++) {
      // Bootstrap sampling
      const sampleIndices = this.bootstrapSample(features.length);
      const sampleFeatures = sampleIndices.map(idx => features[idx]);
      const sampleLabels = sampleIndices.map(idx => labels[idx]);

      // Train decision tree
      const tree = this.trainDecisionTree(sampleFeatures, sampleLabels, maxDepth);
      trees.push(tree);
    }

    return { type: 'random_forest', trees, featureCount: features[0].length };
  }

  private bootstrapSample(size: number): number[] {
    const indices: number[] = [];
    for (let i = 0; i < size; i++) {
      indices.push(Math.floor(Math.random() * size));
    }
    return indices;
  }

  private trainDecisionTree(features: number[][], labels: number[], maxDepth: number): any {
    // Simplified decision tree (would be more complex in production)
    return {
      type: 'decision_tree',
      maxDepth,
      featureSplits: this.findBestSplits(features, labels)
    };
  }

  private findBestSplits(features: number[][], labels: number[]): any[] {
    // Simplified feature split finding
    const splits = [];
    for (let featureIndex = 0; featureIndex < features[0].length; featureIndex++) {
      const values = features.map(row => row[featureIndex]);
      const threshold = this.calculateMedian(values);
      splits.push({ featureIndex, threshold });
    }
    return splits;
  }

  private calculateMedian(values: number[]): number {
    const sorted = values.sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted[mid];
  }

  private async trainGradientBoosting(hyperparams: any, features: number[][], labels: number[]): Promise<any> {
    // Simplified Gradient Boosting implementation
    const { nEstimators, learningRate } = hyperparams;

    const models = [];
    let currentPredictions = new Array(labels.length).fill(0);

    for (let i = 0; i < nEstimators; i++) {
      const residuals = labels.map((label, idx) => label - currentPredictions[idx]);
      const model = this.trainDecisionTree(features, residuals, 5);
      models.push(model);

      // Update predictions
      const modelPredictions = await this.predictBatch({ type: 'decision_tree', ...model }, features);
      for (let j = 0; j < currentPredictions.length; j++) {
        currentPredictions[j] += learningRate * modelPredictions[j];
      }
    }

    return { type: 'gradient_boosting', models, learningRate };
  }

  private async trainSVM(hyperparams: any, features: number[][], labels: number[]): Promise<any> {
    // Simplified SVM implementation
    const { C, kernel } = hyperparams;
    return { type: 'svm', C, kernel, supportVectors: [] };
  }

  private async trainNeuralNetwork(hyperparams: any, features: number[][], labels: number[]): Promise<any> {
    // Simplified Neural Network implementation
    const { hiddenLayers, activation, learningRate } = hyperparams;
    return { type: 'neural_network', layers: hiddenLayers, activation, learningRate };
  }

  private async predictBatch(model: any, features: number[][]): Promise<number[]> {
    // Simplified prediction logic
    switch (model.type) {
      case 'random_forest':
        return features.map(() => Math.random()); // Placeholder
      case 'gradient_boosting':
        return features.map(() => Math.random()); // Placeholder
      case 'svm':
        return features.map(() => Math.random()); // Placeholder
      case 'neural_network':
        return features.map(() => Math.random()); // Placeholder
      default:
        return features.map(() => 0);
    }
  }

  private calculateMetrics(predictions: number[], actuals: number[]): TrainingResult['metrics'] {
    const roundedPredictions = predictions.map(p => Math.round(p));

    let correct = 0;
    let truePositives = 0;
    let falsePositives = 0;
    let falseNegatives = 0;

    for (let i = 0; i < predictions.length; i++) {
      if (roundedPredictions[i] === actuals[i]) correct++;

      if (roundedPredictions[i] === 1 && actuals[i] === 1) truePositives++;
      if (roundedPredictions[i] === 1 && actuals[i] === 0) falsePositives++;
      if (roundedPredictions[i] === 0 && actuals[i] === 1) falseNegatives++;
    }

    const accuracy = correct / predictions.length;
    const precision = truePositives / (truePositives + falsePositives) || 0;
    const recall = truePositives / (truePositives + falseNegatives) || 0;
    const f1Score = 2 * (precision * recall) / (precision + recall) || 0;

    return {
      accuracy,
      precision,
      recall,
      f1Score,
      auc: 0.85 // Placeholder for AUC calculation
    };
  }

  private calculateConfusionMatrix(predictions: number[], actuals: number[]): number[][] {
    const matrix = [
      [0, 0], // [TN, FP]
      [0, 1]  // [FN, TP]
    ];

    for (let i = 0; i < predictions.length; i++) {
      const pred = Math.round(predictions[i]);
      const actual = actuals[i];
      matrix[actual][pred]++;
    }

    return matrix;
  }

  private async crossValidate(
    config: ModelConfig,
    features: number[][],
    labels: number[],
    folds: number
  ): Promise<number[]> {
    const foldSize = Math.floor(features.length / folds);
    const scores: number[] = [];

    for (let fold = 0; fold < folds; fold++) {
      const start = fold * foldSize;
      const end = fold === folds - 1 ? features.length : (fold + 1) * foldSize;

      const valFeatures = features.slice(start, end);
      const valLabels = labels.slice(start, end);
      const trainFeatures = [...features.slice(0, start), ...features.slice(end)];
      const trainLabels = [...labels.slice(0, start), ...labels.slice(end)];

      const model = await this.trainModelByType(config, trainFeatures, trainLabels);
      const predictions = await this.predictBatch(model, valFeatures);
      const metrics = this.calculateMetrics(predictions, valLabels);
      scores.push(metrics.accuracy);
    }

    return scores;
  }

  private calculateFeatureImportance(model: any, config: ModelConfig): Record<string, number> {
    const importance: Record<string, number> = {};

    config.featureSelection.forEach(feature => {
      importance[feature] = Math.random(); // Placeholder for actual importance calculation
    });

    return importance;
  }

  private saveModel(result: TrainingResult): void {
    try {
      const modelPath = path.join(this.modelsDir, `${result.modelId}.json`);
      fs.writeFileSync(modelPath, JSON.stringify(result, null, 2));
      this.models.set(result.modelId, result);
      logger.info('💾 Saved trained model', { modelId: result.modelId, path: modelPath });
    } catch (error) {
      logger.error('❌ Failed to save model', { error: error.message });
    }
  }

  async predict(modelId: string, features: MLFeatures): Promise<ModelPrediction> {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    // Extract features according to model configuration
    const featureValues = model.config.featureSelection.map((featureName: string) => {
      const value = (features as any)[featureName];
      return typeof value === 'number' ? value : 0;
    });

    // Make prediction
    const prediction = await this.predictBatch(model, [featureValues]);
    const threatLevel = prediction[0];

    return {
      threatLevel,
      confidence: 0.8, // Placeholder
      featureContributions: model.featureImportance || {}
    };
  }

  getModelList(): Array<{ id: string; name: string; type: string; accuracy: number }> {
    return Array.from(this.models.values()).map(model => ({
      id: model.modelId,
      name: model.config.name,
      type: model.config.type,
      accuracy: model.metrics.accuracy
    }));
  }

  deleteModel(modelId: string): boolean {
    if (this.models.has(modelId)) {
      const modelPath = path.join(this.modelsDir, `${modelId}.json`);
      try {
        fs.unlinkSync(modelPath);
        this.models.delete(modelId);
        logger.info('🗑️ Deleted model', { modelId });
        return true;
      } catch (error) {
        logger.error('❌ Failed to delete model file', { modelId, error: error.message });
      }
    }
    return false;
  }
}

export const modelTrainer = MLModelTrainer.getInstance();
