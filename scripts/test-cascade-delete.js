// scripts/test-cascade-delete.js
// Test script to validate cascade delete functionality
// Run this script to test the employee cascade deletion

const mongoose = require('mongoose');
require('dotenv').config();

// Models
const Employee = require('../models/Employee');
const AssignedSchedule = require('../models/AssignedSchedule');
const ProjectMaster = require('../models/ProjectMaster');

// Helpers
const { checkEmployeeDependencies, cascadeDeleteEmployees } = require('../utils/cascadeHelpers');

async function testCascadeDelete() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Step 1: Create test data
    console.log('\n🔧 Creating test data...');
    
    // Create a test employee
    const testEmployee = await Employee.create({
      empCode: 'TEST001',
      name: 'Test Employee',
      payrollCompany: 'Test Company',
      division: 'Test Division',
      location: 'Test Location',
      designation: 'Test Designation',
      homePractice: 'Test Practice',
      practiceManager: 'Test Manager'
    });
    console.log(`✅ Created test employee: ${testEmployee.empCode}`);

    // Create a test project (if needed)
    let testProject = await ProjectMaster.findOne({ projectName: 'Test Project' });
    if (!testProject) {
      testProject = await ProjectMaster.create({
        projectName: 'Test Project',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-12-31'),
        projectManager: 'Test Manager',
        cbslClient: 'Test CBSL Client',
        dihClient: 'Test DIH Client'
      });
    }
    console.log(`✅ Using test project: ${testProject.projectName}`);

    // Create test AssignedSchedule records
    const testSchedules = [];
    for (let i = 1; i <= 3; i++) {
      const schedule = await AssignedSchedule.create({
        employee: testEmployee._id,
        project: testProject._id,
        dailyHours: {
          '1-Jan-2024': 8,
          '2-Jan-2024': 8,
          '3-Jan-2024': 8
        },
        role: 'Test Role',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-03'),
        scheduledBy: 'Test Admin',
        scheduledAt: new Date()
      });
      testSchedules.push(schedule);
    }
    console.log(`✅ Created ${testSchedules.length} test schedule assignments`);

    // Step 2: Test dependency checking
    console.log('\n🔍 Testing dependency checking...');
    const dependencies = await checkEmployeeDependencies([testEmployee.empCode]);
    console.log('Dependencies check result:', {
      employeesFound: dependencies.employeesFound,
      schedulesAffected: dependencies.schedulesAffected,
      scheduleDetails: dependencies.scheduleDetails.map(s => ({
        employee: s.employeeCode,
        project: s.projectName
      }))
    });

    // Step 3: Test cascade deletion
    console.log('\n🗑️ Testing cascade deletion...');
    const deleteResult = await cascadeDeleteEmployees([testEmployee.empCode]);
    console.log('Cascade delete result:', {
      success: deleteResult.success,
      deletedEmployees: deleteResult.deletedEmployees,
      deletedSchedules: deleteResult.deletedSchedules
    });

    // Step 4: Verify deletion
    console.log('\n✅ Verifying deletion...');
    const remainingEmployee = await Employee.findOne({ empCode: testEmployee.empCode });
    const remainingSchedules = await AssignedSchedule.find({ employee: testEmployee._id });
    
    console.log('Verification results:');
    console.log(`- Employee still exists: ${remainingEmployee ? 'YES (❌ FAILED)' : 'NO (✅ SUCCESS)'}`);
    console.log(`- Schedules still exist: ${remainingSchedules.length > 0 ? `YES - ${remainingSchedules.length} remaining (❌ FAILED)` : 'NO (✅ SUCCESS)'}`);

    // Clean up test project if we created it
    await ProjectMaster.deleteOne({ _id: testProject._id });
    console.log('✅ Cleaned up test project');

    if (!remainingEmployee && remainingSchedules.length === 0) {
      console.log('\n🎉 CASCADE DELETE TEST PASSED! Employee and all related schedules were successfully deleted.');
    } else {
      console.log('\n❌ CASCADE DELETE TEST FAILED! Some data was not properly deleted.');
    }

  } catch (error) {
    console.error('❌ Test failed with error:', error);
  } finally {
    await mongoose.connection.close();
    console.log('\n🔌 Disconnected from MongoDB');
    process.exit(0);
  }
}

// Run the test
console.log('🧪 Starting Cascade Delete Test...');
testCascadeDelete();
