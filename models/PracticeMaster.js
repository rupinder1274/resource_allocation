const mongoose = require('mongoose');

const practiceMasterSchema = new mongoose.Schema({
  practiceName: { type: String, required: true },
  practiceManager: { type: String }
});

module.exports = mongoose.model('PracticeMaster', practiceMasterSchema);
