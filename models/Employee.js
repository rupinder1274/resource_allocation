// models/Employee.js
const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
  empCode: { type: String, required: true, unique: true },
  name: String,
  payrollCompany: String,
  division: String,
  location: String,
  designation: String,
  homePractice: String,
  practiceManager: String,
  project: String
});

// Pre-remove middleware to handle cascade deletion
employeeSchema.pre('deleteOne', { document: false, query: true }, async function() {
  const doc = await this.model.findOne(this.getFilter());
  if (doc) {
    // Import AssignedSchedule model - we need to do this inside the function to avoid circular dependency
    const AssignedSchedule = mongoose.model('AssignedSchedule');
    const deleteResult = await AssignedSchedule.deleteMany({ employee: doc._id });
    console.log(`🗑️ Pre-hook cascade delete: Removed ${deleteResult.deletedCount} assigned schedule records for employee ${doc.empCode}`);
  }
});

// Pre-remove middleware for deleteMany operations
employeeSchema.pre('deleteMany', { document: false, query: true }, async function() {
  const docs = await this.model.find(this.getFilter());
  if (docs.length > 0) {
    const employeeIds = docs.map(doc => doc._id);
    // Import AssignedSchedule model - we need to do this inside the function to avoid circular dependency
    const AssignedSchedule = mongoose.model('AssignedSchedule');
    const deleteResult = await AssignedSchedule.deleteMany({ employee: { $in: employeeIds } });
    console.log(`🗑️ Pre-hook cascade delete: Removed ${deleteResult.deletedCount} assigned schedule records for ${docs.length} employees`);
  }
});

module.exports = mongoose.model('Employee', employeeSchema);
