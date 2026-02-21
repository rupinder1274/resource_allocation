const mongoose = require('mongoose');

const assignedScheduleSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee' },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'ProjectMaster' },
  practice: { type: mongoose.Schema.Types.ObjectId, ref: 'PracticeMaster' },
  dailyHours: { type: Object, default: {} }, // { '1-Jul': 8, '2-Jul': 6, ... }
  role: String,
  startDate: Date,
  endDate: Date,
  scheduledBy: String,
  scheduledAt: Date
});


module.exports = mongoose.model('AssignedSchedule', assignedScheduleSchema);