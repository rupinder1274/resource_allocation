const mongoose = require('mongoose');

const projectMasterSchema = new mongoose.Schema({
  projectName: { type: String, required: true },
  startDate: { type: Date },
  endDate: { type: Date },
  projectManager: { type: String },
  cbslClient: { type: String },
  dihClient: { type: String }
});

module.exports = mongoose.model('ProjectMaster', projectMasterSchema);
