# Issue #831: Real-Time Collaborative Editing with CRDTs

## Overview

Implemented a backend-first real-time collaboration system that supports concurrent edits, conflict-free merges, offline sync replay, and low-latency multi-user synchronization.

## Core Architecture

- **CRDT model:** RGA-style text CRDT using tombstones for conflict-free insert/delete merge
- **LWW registers:** Deterministic Last-Writer-Wins merges for note fields and spreadsheet cells
- **Versioned operation log:** Server-versioned operations for offline replay and delta sync
- **Vector clock tracking:** Per-actor counters in document state for merge awareness
- **Optimistic concurrency:** Retry logic for concurrent save races

## Added Files

- `models/CollaborativeDocument.js`
- `services/realtimeCollaborationService.js`
- `routes/realtimeCollaboration.js`

## Updated Files

- `server.js`

## REST APIs

- `POST /api/realtime-collab/documents` - create collaborative document
- `GET /api/realtime-collab/documents/:id` - get snapshot/state
- `POST /api/realtime-collab/documents/:id/sync` - submit offline or realtime ops
- `GET /api/realtime-collab/documents/:id/changes?sinceVersion=N` - fetch deltas
- `POST /api/realtime-collab/documents/:id/presence` - update online presence

## Socket.IO Events

- Client → Server:
  - `collab:join`
  - `collab:operations`
  - `collab:leave`
- Server → Client:
  - `collab:snapshot`
  - `collab:operations`
  - `collab:ack`
  - `collab:presence`
  - `collab:error`

## Distributed Real-Time Sync

- Redis pub/sub channel: `expenseflow:collab`
- Cross-instance operation fan-out with `serverInstanceId` dedupe to avoid local echo duplication

## Offline Editing Support

Clients can queue operations while offline and replay them via `/sync`. The server performs idempotent merges using operation IDs and returns authoritative versions and deltas.

## Conflict Resolution Guarantees

- Concurrent text inserts at same position resolve deterministically by operation ID ordering
- Deletes are tombstone-based and idempotent
- Cell/field updates resolve deterministically by `(lamport, actorId, opId)` ordering

## Scalability/Latency Notes

- Room-based websocket broadcasting minimizes unnecessary fan-out
- Redis pub/sub enables horizontal scaling across multiple API instances
- Versioned change feed allows efficient incremental sync
