require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/resource-allocation', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const initializeUsers = async () => {
  try {
    console.log('🔄 Initializing users in database...');

    // Check if users already exist
    const existingUsers = await User.countDocuments();
    if (existingUsers > 0) {
      console.log(`ℹ️  Users already exist in database (${existingUsers} users found). Skipping initialization.`);
      console.log('💡 If you want to reset users, please delete them manually first.');
      return;
    }

    // Create default users
    const defaultUsers = [
      {
        email: 'admin@cbsl.com',
        password: bcrypt.hashSync('admin123', 10),
        role: 'admin'
      },
      {
        email: 'manager.DIH@cbsl.com',
        password: bcrypt.hashSync('123', 10),
        role: 'manager'
      },
      {
        email: 'manager.ABC@cbsl.com',
        password: bcrypt.hashSync('abc123', 10),
        role: 'manager'
      },
      {
        email: 'manager.XYZ@cbsl.com',
        password: bcrypt.hashSync('xyz123', 10),
        role: 'manager'
      },
      {
        email: 'manager.PQR@cbsl.com',
        password: bcrypt.hashSync('pqr123', 10),
        role: 'manager'
      }
    ];

    // Insert users into database
    await User.insertMany(defaultUsers);
    
    console.log('✅ Successfully initialized users in database!');
    console.log('📋 Default users created:');
    defaultUsers.forEach(user => {
      console.log(`   - ${user.email} (${user.role})`);
    });
    
    console.log('\n🔑 Default passwords:');
    console.log('   - admin@cbsl.com: admin123');
    console.log('   - manager.DIH@cbsl.com: 123');
    console.log('   - manager.ABC@cbsl.com: abc123');
    console.log('   - manager.XYZ@cbsl.com: xyz123');
    console.log('   - manager.PQR@cbsl.com: pqr123');

  } catch (error) {
    console.error('❌ Error initializing users:', error);
    
    // Handle duplicate key error
    if (error.code === 11000) {
      console.log('ℹ️  Some users may already exist. This is normal if the script was run before.');
    }
  } finally {
    mongoose.connection.close();
    console.log('\n🔌 Database connection closed.');
  }
};

// Run the initialization
initializeUsers();
