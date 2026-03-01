const express = require('express');
const auth = require('../middleware/auth');
const realtimeCollaborationService = require('../services/realtimeCollaborationService');

const router = express.Router();

router.post('/documents', auth, async (req, res) => {
  try {
    const { title, docType, workspace, participants } = req.body;

    if (!title) {
      return res.status(400).json({
        success: false,
        error: 'title is required'
      });
    }

    const created = await realtimeCollaborationService.createDocument({
      title,
      docType,
      workspace,
      createdBy: req.user._id,
      participants: Array.isArray(participants) ? participants : []
    });

    return res.status(201).json({
      success: true,
      document: created
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/documents/:id', auth, async (req, res) => {
  try {
    const document = await realtimeCollaborationService.getDocument(req.params.id, req.user._id);

    return res.json({
      success: true,
      document
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

router.post('/documents/:id/sync', auth, async (req, res) => {
  try {
    const { operations, deviceId } = req.body;

    const result = await realtimeCollaborationService.applyOperations(
      req.params.id,
      req.user._id,
      deviceId,
      Array.isArray(operations) ? operations : []
    );

    return res.json({
      success: true,
      result
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

router.get('/documents/:id/changes', auth, async (req, res) => {
  try {
    const sinceVersion = Number(req.query.sinceVersion) || 0;
    const result = await realtimeCollaborationService.getChangesSince(
      req.params.id,
      req.user._id,
      sinceVersion
    );

    return res.json({
      success: true,
      result
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

router.post('/documents/:id/presence', auth, async (req, res) => {
  try {
    const status = await realtimeCollaborationService.markPresence(
      req.params.id,
      req.user._id,
      req.body?.isOnline !== false
    );

    return res.json({
      success: true,
      status
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
