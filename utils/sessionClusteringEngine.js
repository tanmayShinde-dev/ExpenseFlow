/**
 * Session Clustering Engine
 * Issue #879: Cross-Session Threat Correlation
 * 
 * Advanced clustering algorithms for grouping sessions by behavioral similarity
 */

class SessionClusteringEngine {
  constructor(options = {}) {
    this.minClusterSize = options.minClusterSize || 2;
    this.maxDistance = options.maxDistance || 0.5;
    this.clusteringMethod = options.clusteringMethod || 'DBSCAN';
    this.featureWeights = options.featureWeights || this.getDefaultWeights();
  }
  
  getDefaultWeights() {
    return {
      ip: 0.3,
      deviceFingerprint: 0.25,
      anomalyScore: 0.2,
      attackVector: 0.15,
      timeWindow: 0.1
    };
  }
  
  /**
   * Cluster sessions by behavioral similarity
   */
  async clusterSessions(sessions) {
    if (!sessions || sessions.length < this.minClusterSize) {
      return [];
    }
    
    // Compute feature vectors for all sessions
    const featureVectors = sessions.map(session => this.extractFeatureVector(session));
    
    // Compute pairwise distance matrix
    const distanceMatrix = this.computeDistanceMatrix(featureVectors);
    
    // Apply clustering algorithm
    let clusters;
    switch (this.clusteringMethod) {
      case 'DBSCAN':
        clusters = this.dbscan(distanceMatrix, this.maxDistance, this.minClusterSize);
        break;
      case 'HIERARCHICAL':
        clusters = this.hierarchicalClustering(distanceMatrix, this.maxDistance);
        break;
      case 'KMEANS':
        clusters = this.kmeans(featureVectors, Math.ceil(sessions.length / 3));
        break;
      default:
        clusters = this.dbscan(distanceMatrix, this.maxDistance, this.minClusterSize);
    }
    
    // Map cluster indices back to sessions
    return this.mapClustersToSessions(clusters, sessions);
  }
  
  /**
   * Extract feature vector from session
   */
  extractFeatureVector(session) {
    const features = {
      ip: this.hashFeature(session.ip || ''),
      deviceFingerprint: this.hashFeature(session.deviceFingerprint || ''),
      anomalyScore: session.anomalyScore || 0,
      attackVector: this.encodeAttackVector(session.attackVector),
      timestamp: session.timestamp ? session.timestamp.getTime() : Date.now(),
      location: this.encodeLocation(session.location),
      userAgent: this.hashFeature(session.userAgent || ''),
      riskScore: session.riskScore || 0
    };
    
    return features;
  }
  
  /**
   * Hash string features to numeric values
   */
  hashFeature(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash) / 2147483647; // Normalize to [0, 1]
  }
  
  /**
   * Encode attack vector as numeric value
   */
  encodeAttackVector(attackVector) {
    const vectors = {
      'BRUTE_FORCE': 0.1,
      'CREDENTIAL_STUFFING': 0.2,
      'SESSION_HIJACKING': 0.3,
      'PRIVILEGE_ESCALATION': 0.4,
      'SQL_INJECTION': 0.5,
      'XSS': 0.6,
      'CSRF': 0.7,
      'API_ABUSE': 0.8,
      'DATA_EXFILTRATION': 0.9
    };
    
    return vectors[attackVector] || 0;
  }
  
  /**
   * Encode location as numeric value
   */
  encodeLocation(location) {
    if (!location || !location.latitude || !location.longitude) {
      return { lat: 0, lon: 0 };
    }
    
    return {
      lat: location.latitude / 90, // Normalize to [-1, 1]
      lon: location.longitude / 180
    };
  }
  
  /**
   * Compute distance between two feature vectors
   */
  computeDistance(features1, features2) {
    let distance = 0;
    
    // IP similarity (exact match)
    const ipDistance = features1.ip === features2.ip ? 0 : 1;
    distance += ipDistance * this.featureWeights.ip;
    
    // Device fingerprint similarity
    const deviceDistance = features1.deviceFingerprint === features2.deviceFingerprint ? 0 : 1;
    distance += deviceDistance * this.featureWeights.deviceFingerprint;
    
    // Anomaly score similarity
    const anomalyDistance = Math.abs(features1.anomalyScore - features2.anomalyScore);
    distance += anomalyDistance * this.featureWeights.anomalyScore;
    
    // Attack vector similarity
    const vectorDistance = Math.abs(features1.attackVector - features2.attackVector);
    distance += vectorDistance * this.featureWeights.attackVector;
    
    // Time window proximity (1 hour = 0 distance, 24 hours = 1 distance)
    const timeDiff = Math.abs(features1.timestamp - features2.timestamp);
    const timeDistance = Math.min(timeDiff / (24 * 60 * 60 * 1000), 1);
    distance += timeDistance * this.featureWeights.timeWindow;
    
    return distance;
  }
  
  /**
   * Compute pairwise distance matrix
   */
  computeDistanceMatrix(featureVectors) {
    const n = featureVectors.length;
    const matrix = Array(n).fill(null).map(() => Array(n).fill(0));
    
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const distance = this.computeDistance(featureVectors[i], featureVectors[j]);
        matrix[i][j] = distance;
        matrix[j][i] = distance;
      }
    }
    
    return matrix;
  }
  
  /**
   * DBSCAN clustering algorithm
   */
  dbscan(distanceMatrix, eps, minPts) {
    const n = distanceMatrix.length;
    const labels = Array(n).fill(-1); // -1 = unvisited, 0+ = cluster ID
    const visited = Array(n).fill(false);
    let clusterId = 0;
    
    for (let i = 0; i < n; i++) {
      if (visited[i]) continue;
      
      visited[i] = true;
      const neighbors = this.regionQuery(distanceMatrix, i, eps);
      
      if (neighbors.length < minPts) {
        labels[i] = -1; // Noise point
      } else {
        this.expandCluster(distanceMatrix, labels, visited, i, neighbors, clusterId, eps, minPts);
        clusterId++;
      }
    }
    
    return this.groupByCluster(labels);
  }
  
  /**
   * Find neighbors within eps distance
   */
  regionQuery(distanceMatrix, pointIdx, eps) {
    const neighbors = [];
    for (let i = 0; i < distanceMatrix[pointIdx].length; i++) {
      if (distanceMatrix[pointIdx][i] <= eps) {
        neighbors.push(i);
      }
    }
    return neighbors;
  }
  
  /**
   * Expand cluster from seed point
   */
  expandCluster(distanceMatrix, labels, visited, pointIdx, neighbors, clusterId, eps, minPts) {
    labels[pointIdx] = clusterId;
    
    let i = 0;
    while (i < neighbors.length) {
      const neighborIdx = neighbors[i];
      
      if (!visited[neighborIdx]) {
        visited[neighborIdx] = true;
        const neighborNeighbors = this.regionQuery(distanceMatrix, neighborIdx, eps);
        
        if (neighborNeighbors.length >= minPts) {
          neighbors = neighbors.concat(neighborNeighbors);
        }
      }
      
      if (labels[neighborIdx] === -1) {
        labels[neighborIdx] = clusterId;
      }
      
      i++;
    }
  }
  
  /**
   * Hierarchical clustering
   */
  hierarchicalClustering(distanceMatrix, threshold) {
    const n = distanceMatrix.length;
    const clusters = Array.from({ length: n }, (_, i) => [i]);
    
    while (clusters.length > 1) {
      // Find closest pair of clusters
      let minDistance = Infinity;
      let mergeI = 0, mergeJ = 1;
      
      for (let i = 0; i < clusters.length; i++) {
        for (let j = i + 1; j < clusters.length; j++) {
          const distance = this.clusterDistance(distanceMatrix, clusters[i], clusters[j]);
          if (distance < minDistance) {
            minDistance = distance;
            mergeI = i;
            mergeJ = j;
          }
        }
      }
      
      // Stop if minimum distance exceeds threshold
      if (minDistance > threshold) break;
      
      // Merge clusters
      clusters[mergeI] = clusters[mergeI].concat(clusters[mergeJ]);
      clusters.splice(mergeJ, 1);
    }
    
    return clusters;
  }
  
  /**
   * Compute distance between two clusters (average linkage)
   */
  clusterDistance(distanceMatrix, cluster1, cluster2) {
    let totalDistance = 0;
    let count = 0;
    
    for (const i of cluster1) {
      for (const j of cluster2) {
        totalDistance += distanceMatrix[i][j];
        count++;
      }
    }
    
    return totalDistance / count;
  }
  
  /**
   * K-means clustering
   */
  kmeans(featureVectors, k, maxIterations = 100) {
    const n = featureVectors.length;
    k = Math.min(k, n);
    
    // Initialize centroids randomly
    let centroids = this.initializeCentroids(featureVectors, k);
    let assignments = Array(n).fill(0);
    let changed = true;
    let iterations = 0;
    
    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;
      
      // Assign points to nearest centroid
      for (let i = 0; i < n; i++) {
        const distances = centroids.map(c => this.computeDistance(featureVectors[i], c));
        const nearestCluster = distances.indexOf(Math.min(...distances));
        
        if (assignments[i] !== nearestCluster) {
          assignments[i] = nearestCluster;
          changed = true;
        }
      }
      
      // Update centroids
      centroids = this.updateCentroids(featureVectors, assignments, k);
    }
    
    return this.groupByCluster(assignments);
  }
  
  /**
   * Initialize k centroids using k-means++
   */
  initializeCentroids(featureVectors, k) {
    const centroids = [];
    const n = featureVectors.length;
    
    // Choose first centroid randomly
    centroids.push(featureVectors[Math.floor(Math.random() * n)]);
    
    // Choose remaining centroids with probability proportional to distance
    for (let i = 1; i < k; i++) {
      const distances = featureVectors.map(fv => {
        const minDist = Math.min(...centroids.map(c => this.computeDistance(fv, c)));
        return minDist * minDist;
      });
      
      const totalDistance = distances.reduce((a, b) => a + b, 0);
      const probabilities = distances.map(d => d / totalDistance);
      
      const rand = Math.random();
      let cumulative = 0;
      for (let j = 0; j < n; j++) {
        cumulative += probabilities[j];
        if (rand <= cumulative) {
          centroids.push(featureVectors[j]);
          break;
        }
      }
    }
    
    return centroids;
  }
  
  /**
   * Update centroids based on current assignments
   */
  updateCentroids(featureVectors, assignments, k) {
    const centroids = [];
    
    for (let i = 0; i < k; i++) {
      const clusterPoints = featureVectors.filter((_, idx) => assignments[idx] === i);
      
      if (clusterPoints.length === 0) {
        // Empty cluster, reinitialize randomly
        centroids.push(featureVectors[Math.floor(Math.random() * featureVectors.length)]);
      } else {
        // Compute mean of cluster points
        const centroid = this.computeMeanFeatures(clusterPoints);
        centroids.push(centroid);
      }
    }
    
    return centroids;
  }
  
  /**
   * Compute mean feature vector
   */
  computeMeanFeatures(featureVectors) {
    const n = featureVectors.length;
    const mean = {
      ip: 0,
      deviceFingerprint: 0,
      anomalyScore: 0,
      attackVector: 0,
      timestamp: 0,
      location: { lat: 0, lon: 0 },
      userAgent: 0,
      riskScore: 0
    };
    
    for (const fv of featureVectors) {
      mean.ip += fv.ip;
      mean.deviceFingerprint += fv.deviceFingerprint;
      mean.anomalyScore += fv.anomalyScore;
      mean.attackVector += fv.attackVector;
      mean.timestamp += fv.timestamp;
      mean.location.lat += fv.location.lat;
      mean.location.lon += fv.location.lon;
      mean.userAgent += fv.userAgent;
      mean.riskScore += fv.riskScore;
    }
    
    mean.ip /= n;
    mean.deviceFingerprint /= n;
    mean.anomalyScore /= n;
    mean.attackVector /= n;
    mean.timestamp /= n;
    mean.location.lat /= n;
    mean.location.lon /= n;
    mean.userAgent /= n;
    mean.riskScore /= n;
    
    return mean;
  }
  
  /**
   * Group cluster labels into arrays of indices
   */
  groupByCluster(labels) {
    const clusters = {};
    
    for (let i = 0; i < labels.length; i++) {
      const label = labels[i];
      if (label >= 0) { // Ignore noise points (-1)
        if (!clusters[label]) {
          clusters[label] = [];
        }
        clusters[label].push(i);
      }
    }
    
    return Object.values(clusters).filter(c => c.length >= this.minClusterSize);
  }
  
  /**
   * Map cluster indices back to original sessions
   */
  mapClustersToSessions(clusters, sessions) {
    return clusters.map(clusterIndices => ({
      sessions: clusterIndices.map(idx => sessions[idx]),
      size: clusterIndices.length,
      centroid: this.computeClusterCentroid(clusterIndices, sessions)
    }));
  }
  
  /**
   * Compute cluster centroid
   */
  computeClusterCentroid(clusterIndices, sessions) {
    const clusterSessions = clusterIndices.map(idx => sessions[idx]);
    const featureVectors = clusterSessions.map(s => this.extractFeatureVector(s));
    return this.computeMeanFeatures(featureVectors);
  }
  
  /**
   * Compute cluster quality metrics
   */
  computeClusterQuality(clusters, sessions) {
    if (clusters.length === 0) {
      return { silhouetteScore: 0, cohesion: 0, separation: 0 };
    }
    
    const featureVectors = sessions.map(s => this.extractFeatureVector(s));
    const assignments = this.getClusterAssignments(clusters, sessions.length);
    
    // Compute silhouette score
    const silhouetteScores = [];
    for (let i = 0; i < sessions.length; i++) {
      const clusterIdx = assignments[i];
      if (clusterIdx < 0) continue; // Skip noise points
      
      const cluster = clusters[clusterIdx];
      const a = this.averageIntraClusterDistance(i, cluster, featureVectors);
      const b = this.minInterClusterDistance(i, clusterIdx, clusters, featureVectors);
      
      const silhouette = (b - a) / Math.max(a, b);
      silhouetteScores.push(silhouette);
    }
    
    const avgSilhouette = silhouetteScores.reduce((a, b) => a + b, 0) / silhouetteScores.length;
    
    return {
      silhouetteScore: avgSilhouette,
      clusterCount: clusters.length,
      avgClusterSize: clusters.reduce((a, c) => a + c.length, 0) / clusters.length
    };
  }
  
  /**
   * Get cluster assignment for each session
   */
  getClusterAssignments(clusters, sessionCount) {
    const assignments = Array(sessionCount).fill(-1);
    
    clusters.forEach((cluster, clusterIdx) => {
      cluster.forEach(sessionIdx => {
        assignments[sessionIdx] = clusterIdx;
      });
    });
    
    return assignments;
  }
  
  /**
   * Average intra-cluster distance
   */
  averageIntraClusterDistance(pointIdx, cluster, featureVectors) {
    if (cluster.length <= 1) return 0;
    
    let totalDistance = 0;
    let count = 0;
    
    for (const otherIdx of cluster) {
      if (otherIdx !== pointIdx) {
        totalDistance += this.computeDistance(featureVectors[pointIdx], featureVectors[otherIdx]);
        count++;
      }
    }
    
    return count > 0 ? totalDistance / count : 0;
  }
  
  /**
   * Minimum inter-cluster distance
   */
  minInterClusterDistance(pointIdx, clusterIdx, clusters, featureVectors) {
    let minDistance = Infinity;
    
    clusters.forEach((cluster, otherClusterIdx) => {
      if (otherClusterIdx === clusterIdx) return;
      
      let clusterDistance = 0;
      for (const otherIdx of cluster) {
        clusterDistance += this.computeDistance(featureVectors[pointIdx], featureVectors[otherIdx]);
      }
      clusterDistance /= cluster.length;
      
      if (clusterDistance < minDistance) {
        minDistance = clusterDistance;
      }
    });
    
    return minDistance;
  }
}

module.exports = SessionClusteringEngine;
