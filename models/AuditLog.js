const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  manager: {
    type: String, // user email or ID (supports both admin and manager)
    required: true
  },
  managerName: {
    type: String, // user name for display
    required: false
  },
  userRole: {
    type: String, // user role: admin or manager
    required: true,
    enum: ['admin', 'manager'],
    default: 'manager'
  },
  action: {
    type: String, // create, update, delete, bulk_assign, bulk_replace
    required: true,
    enum: ['create', 'update', 'delete', 'bulk_assign', 'bulk_replace']
  },
  assignmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AssignedSchedule',
    required: false
  },
  employeeCode: {
    type: String, // employee code affected
    required: false
  },
  employeeName: {
    type: String, // employee name affected
    required: false
  },
  projectName: {
    type: String, // project name affected
    required: false
  },
  description: {
    type: String, // detailed description of what was changed
    required: true
  },
  changes: {
    type: Object, // specific changes made (field-by-field)
    required: false
  },
  before: {
    type: Object, // complete previous state for revert
    required: false
  },
  after: {
    type: Object, // complete new state
    required: false
  },
  route: {
    type: String, // which page/route (manager-calendar, manager-schedule, etc.)
    required: true
  },
  ipAddress: {
    type: String, // IP address of the manager
    required: false
  },
  userAgent: {
    type: String, // browser/device info
    required: false
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  canRevert: {
    type: Boolean,
    default: true
  },
  isReverted: {
    type: Boolean,
    default: false
  },
  revertedBy: {
    type: String, // admin who reverted
    required: false
  },
  revertedAt: {
    type: Date,
    required: false
  },
  revertReason: {
    type: String, // reason for revert
    required: false
  }
});

// Index for better query performance
AuditLogSchema.index({ timestamp: -1 });
AuditLogSchema.index({ manager: 1, timestamp: -1 });
AuditLogSchema.index({ assignmentId: 1 });

module.exports = mongoose.model('AuditLog', AuditLogSchema);
