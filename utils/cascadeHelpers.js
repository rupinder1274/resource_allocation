// utils/cascadeHelpers.js
// This is a placeholder file to resolve the missing module error.
// Add your cascade helper functions here as needed.

const Employee = require('../models/Employee');
const AssignedSchedule = require('../models/AssignedSchedule');

/**
 * Check what dependencies (AssignedSchedule records) would be affected for given employee codes.
 * @param {string[]} empCodes
 * @returns {Promise<object>} { employeesFound, schedulesAffected, scheduleDetails }
 */
async function checkEmployeeDependencies(empCodes) {
  try {
    if (!Array.isArray(empCodes)) empCodes = [empCodes];
    // Find employees
    const employees = await Employee.find({ empCode: { $in: empCodes } }).lean();
    const employeeMap = {};
    employees.forEach(e => { employeeMap[String(e._id)] = e; });

    const employeeIds = employees.map(e => e._id);
    // Find schedules referencing these employees
    const schedules = await AssignedSchedule.find({ employee: { $in: employeeIds } }).populate('project employee').lean();

    const scheduleDetails = schedules.map(s => ({
      assignmentId: s._id,
      employeeId: s.employee?._id || null,
      employeeCode: s.employee?.empCode || '',
      employeeName: s.employee?.name || '',
      projectId: s.project?._id || null,
      projectName: s.project?.projectName || '',
      dates: s.dailyHours ? Object.keys(s.dailyHours) : []
    }));

    return {
      employeesFound: employees.length,
      schedulesAffected: schedules.length,
      scheduleDetails
    };
  } catch (err) {
    throw err;
  }
}

/**
 * Cascade delete employees and their related AssignedSchedule records.
 * @param {string[]} empCodes
 * @param {object} auditInfo - optional info (adminEmail, route)
 * @returns {Promise<object>} { success, deletedEmployees, deletedSchedules, scheduleDetails }
 */
async function cascadeDeleteEmployees(empCodes, auditInfo = {}) {
  try {
    if (!Array.isArray(empCodes)) empCodes = [empCodes];

    // Find employees
    const employees = await Employee.find({ empCode: { $in: empCodes } }).lean();
    if (employees.length === 0) {
      return { success: true, deletedEmployees: 0, deletedSchedules: 0, scheduleDetails: [] };
    }

    const employeeIds = employees.map(e => e._id);

    // Get schedules to return details for audit
    const schedules = await AssignedSchedule.find({ employee: { $in: employeeIds } }).populate('project employee').lean();
    const scheduleDetails = schedules.map(s => ({
      assignmentId: s._id,
      employeeCode: s.employee?.empCode || '',
      projectName: s.project?.projectName || '',
      dates: s.dailyHours ? Object.keys(s.dailyHours) : []
    }));

    // Delete schedules first
    const delSchedulesRes = await AssignedSchedule.deleteMany({ employee: { $in: employeeIds } });

    // Then delete employees
    const delEmployeesRes = await Employee.deleteMany({ _id: { $in: employeeIds } });

    return {
      success: true,
      deletedEmployees: delEmployeesRes.deletedCount || employees.length,
      deletedSchedules: delSchedulesRes.deletedCount || scheduleDetails.length,
      scheduleDetails
    };
  } catch (err) {
    return { success: false, error: err.message || String(err) };
  }
}

module.exports = {
  checkEmployeeDependencies,
  cascadeDeleteEmployees
};
