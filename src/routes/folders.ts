import express from 'express';
import { body, validationResult } from 'express-validator';
import Folder from '../models/Folder';
import File from '../models/File';
import { authenticate } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { AuthRequest } from '../types';

const router = express.Router();

// Validation middleware
const validateFolder = [
  body('name')
    .isLength({ min: 1, max: 255 })
    .withMessage('Folder name must be between 1 and 255 characters')
    .matches(/^[^<>:"/\\|?*]+$/)
    .withMessage('Folder name contains invalid characters'),
  body('description')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Description cannot exceed 1000 characters'),
  body('parent')
    .optional()
    .isMongoId()
    .withMessage('Invalid parent folder ID'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array')
];

// @route   GET /api/folders
// @desc    Get user's folders
// @access  Private
router.get('/', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { parent } = req.query;

  const query: any = { owner: req.user!._id };
  if (parent) {
    query.parent = parent;
  } else {
    query.parent = { $exists: false };
  }

  const folders = await Folder.find(query)
    .populate('parent', 'name path')
    .sort({ name: 1 });

  res.json({
    success: true,
    message: 'Folders retrieved successfully',
    data: { folders }
  });
}));

// @route   GET /api/folders/:folderId
// @desc    Get a specific folder with contents
// @access  Private
router.get('/:folderId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { folderId } = req.params;

  const folder = await Folder.findOne({ _id: folderId, owner: req.user!._id })
    .populate('parent', 'name path');

  if (!folder) {
    return res.status(404).json({
      success: false,
      message: 'Folder not found'
    });
  }

  // Get subfolders and files
  const [subfolders, files] = await Promise.all([
    Folder.find({ parent: folderId, owner: req.user!._id }).sort({ name: 1 }),
    File.find({ folder: folderId, owner: req.user!._id }).sort({ name: 1 })
  ]);

  res.json({
    success: true,
    message: 'Folder retrieved successfully',
    data: {
      folder,
      subfolders,
      files
    }
  });
}));

// @route   POST /api/folders
// @desc    Create a new folder
// @access  Private
router.post('/', authenticate, validateFolder, asyncHandler(async (req: AuthRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { name, description, parent, tags } = req.body;

  // Check if folder with same name exists in parent
  const existingFolder = await Folder.findOne({
    name,
    parent: parent || { $exists: false },
    owner: req.user!._id
  });

  if (existingFolder) {
    return res.status(409).json({
      success: false,
      message: 'A folder with this name already exists in this location'
    });
  }

  // Validate parent folder if provided
  if (parent) {
    const parentFolder = await Folder.findOne({ _id: parent, owner: req.user!._id });
    if (!parentFolder) {
      return res.status(404).json({
        success: false,
        message: 'Parent folder not found'
      });
    }
  }

  const folder = new Folder({
    name,
    description,
    owner: req.user!._id,
    parent: parent || undefined,
    tags: tags || []
  });

  await folder.save();
  await folder.populate('parent', 'name path');

  res.status(201).json({
    success: true,
    message: 'Folder created successfully',
    data: { folder }
  });
}));

// @route   PUT /api/folders/:folderId
// @desc    Update folder
// @access  Private
router.put('/:folderId', authenticate, validateFolder, asyncHandler(async (req: AuthRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }

  const { folderId } = req.params;
  const { name, description, tags } = req.body;

  const folder = await Folder.findOne({ _id: folderId, owner: req.user!._id });
  if (!folder) {
    return res.status(404).json({
      success: false,
      message: 'Folder not found'
    });
  }

  // Check if new name conflicts with existing folder
  if (name && name !== folder.name) {
    const existingFolder = await Folder.findOne({
      name,
      parent: folder.parent,
      owner: req.user!._id,
      _id: { $ne: folderId }
    });

    if (existingFolder) {
      return res.status(409).json({
        success: false,
        message: 'A folder with this name already exists in this location'
      });
    }
  }

  // Update fields
  if (name !== undefined) folder.name = name;
  if (description !== undefined) folder.description = description;
  if (tags !== undefined) folder.tags = tags;

  await folder.save();
  await folder.populate('parent', 'name path');

  res.json({
    success: true,
    message: 'Folder updated successfully',
    data: { folder }
  });
}));

// @route   DELETE /api/folders/:folderId
// @desc    Delete folder
// @access  Private
router.delete('/:folderId', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { folderId } = req.params;

  const folder = await Folder.findOne({ _id: folderId, owner: req.user!._id });
  if (!folder) {
    return res.status(404).json({
      success: false,
      message: 'Folder not found'
    });
  }

  // Check if folder has contents
  const [fileCount, subfolderCount] = await Promise.all([
    File.countDocuments({ folder: folderId, owner: req.user!._id }),
    Folder.countDocuments({ parent: folderId, owner: req.user!._id })
  ]);

  if (fileCount > 0 || subfolderCount > 0) {
    return res.status(400).json({
      success: false,
      message: 'Cannot delete folder with contents. Please move or delete all files and subfolders first.'
    });
  }

  await folder.remove();

  res.json({
    success: true,
    message: 'Folder deleted successfully'
  });
}));

// @route   GET /api/folders/:folderId/path
// @desc    Get folder path hierarchy
// @access  Private
router.get('/:folderId/path', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { folderId } = req.params;

  const folder = await Folder.findOne({ _id: folderId, owner: req.user!._id });
  if (!folder) {
    return res.status(404).json({
      success: false,
      message: 'Folder not found'
    });
  }

  const path: any[] = [];
  let currentFolder = folder;

  // Build path from current folder to root
  while (currentFolder) {
    path.unshift({
      _id: currentFolder._id,
      name: currentFolder.name,
      path: currentFolder.path
    });

    if (currentFolder.parent) {
      currentFolder = await Folder.findById(currentFolder.parent);
    } else {
      break;
    }
  }

  res.json({
    success: true,
    data: { path }
  });
}));

// @route   POST /api/folders/:folderId/move
// @desc    Move folder to different parent
// @access  Private
router.post('/:folderId/move', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { folderId } = req.params;
  const { newParentId } = req.body;

  const folder = await Folder.findOne({ _id: folderId, owner: req.user!._id });
  if (!folder) {
    return res.status(404).json({
      success: false,
      message: 'Folder not found'
    });
  }

  // Validate new parent
  if (newParentId) {
    const newParent = await Folder.findOne({ _id: newParentId, owner: req.user!._id });
    if (!newParent) {
      return res.status(404).json({
        success: false,
        message: 'New parent folder not found'
      });
    }

    // Check for circular reference
    if (newParentId === folderId) {
      return res.status(400).json({
        success: false,
        message: 'Cannot move folder into itself'
      });
    }

    // Check if new parent is a descendant of current folder
    let current = newParent;
    while (current.parent) {
      if (current.parent.toString() === folderId) {
        return res.status(400).json({
          success: false,
          message: 'Cannot move folder into its descendant'
        });
      }
      current = await Folder.findById(current.parent);
      if (!current) break;
    }
  }

  // Check for name conflict in new location
  const existingFolder = await Folder.findOne({
    name: folder.name,
    parent: newParentId || { $exists: false },
    owner: req.user!._id,
    _id: { $ne: folderId }
  });

  if (existingFolder) {
    return res.status(409).json({
      success: false,
      message: 'A folder with this name already exists in the target location'
    });
  }

  folder.parent = newParentId || undefined;
  await folder.save();

  res.json({
    success: true,
    message: 'Folder moved successfully',
    data: { folder }
  });
}));

// @route   GET /api/folders/search
// @desc    Search folders
// @access  Private
router.get('/search', authenticate, asyncHandler(async (req: AuthRequest, res) => {
  const { q } = req.query;

  if (!q) {
    return res.status(400).json({
      success: false,
      message: 'Search query is required'
    });
  }

  const folders = await Folder.find({
    owner: req.user!._id,
    $or: [
      { name: { $regex: q, $options: 'i' } },
      { description: { $regex: q, $options: 'i' } },
      { tags: { $in: [new RegExp(q as string, 'i')] } }
    ]
  })
    .populate('parent', 'name path')
    .sort({ name: 1 })
    .limit(20);

  res.json({
    success: true,
    data: { folders }
  });
}));

export default router; 