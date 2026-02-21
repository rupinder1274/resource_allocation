require('dotenv').config();
// Manager: Assign Schedule POST

const express = require('express');
const session = require('express-session');
const csrf = require('csurf');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');


// Models
const Employee = require('./models/Employee');
const ProjectMaster = require('./models/ProjectMaster');
const PracticeMaster = require('./models/PracticeMaster');
const AssignedSchedule = require('./models/AssignedSchedule');
const AuditLog = require('./models/AuditLog');
const User = require('./models/User');

// Import cascade deletion helpers
const { checkEmployeeDependencies, cascadeDeleteEmployees } = require('./utils/cascadeHelpers');

// Audit logging utility functions
function getUserRolePrefix(req) {
  const userRole = req.session.user?.role || 'manager';
  const userEmail = req.session.user?.email || 'Unknown';
  return userRole === 'admin' ? `Admin ${userEmail}` : `Manager ${userEmail}`;
}

function getRouteContext(req) {
  const userRole = req.session.user?.role || 'manager';
  let route = req.originalUrl || req.route?.path || 'unknown';
  
  // Clean route by removing query parameters
  if (route.includes('?')) {
    route = route.split('?')[0];
  }
  
  // Dynamic route detection based on actual request path
  if (route.includes('/assigned-resources')) {
    return userRole === 'admin' ? 'admin-assigned-resources' : 'manager-assigned-resources';
  } else if (route.includes('/schedule') || route.includes('/assign-project')) {
    return userRole === 'admin' ? 'admin-schedule' : 'manager-schedule';
  } else if (route.includes('/calendar-view')) {
    return userRole === 'admin' ? 'admin-calendar-view' : 'manager-calendar-view';
  } else if (route.includes('/dashboard/admin')) {
    return 'admin-dashboard';
  } else if (route.includes('/dashboard/manager')) {
    return 'manager-dashboard';
  } else {
    // Fallback based on user role if route is unclear
    return userRole === 'admin' ? 'admin-interface' : 'manager-interface';
  }
}

async function logAuditAction(req, action, assignmentId, before, after, description, changes = {}) {
  try {
    // Skip audit logging for Employee, Project, and Practice Master CRUD operations only
    const currentRoute = req.originalUrl || req.route?.path || '';
    const skipRoutes = [
      '/employees/', '/project-master/', '/practice-master/',
      '/upload-employees', '/upload-project-master', '/upload-practice-master',
      '/view-employees', '/view-project-master', '/view-practice-master'
    ];
    
    // Check if this is a master data CRUD operation that should be skipped
    // Only skip if it's a direct master data operation, NOT schedule/assignment operations
    const shouldSkipLogging = skipRoutes.some(skipRoute => currentRoute.includes(skipRoute)) ||
                             (changes && changes.operation && (
                               changes.operation.includes('admin_create_employee') ||
                               changes.operation.includes('admin_update_employee') ||
                               changes.operation.includes('admin_delete_employee') ||
                               changes.operation.includes('admin_create_project') ||
                               changes.operation.includes('admin_update_project') ||
                               changes.operation.includes('admin_delete_project') ||
                               changes.operation.includes('admin_create_practice') ||
                               changes.operation.includes('admin_update_practice') ||
                               changes.operation.includes('admin_delete_practice')
                             ));
    
    if (shouldSkipLogging) {
      //console.log('⚠️ Skipping audit log for master data operation:', description || 'Unknown operation');
      return;
    }

    // Get user info - support both admin and manager users
    const userEmail = req.session.user?.email || 'Unknown';
    const userRole = req.session.user?.role || 'Unknown';
    const userName = req.session.user?.email?.split('@')[0] || 'Unknown';
    
    // Better route detection - differentiate between admin and manager contexts
    let route = currentRoute;
    
    // Clean route by removing query parameters
    if (route.includes('?')) {
      route = route.split('?')[0];
    }
    
    // If the route is generic (like /schedule), determine context from user role and description
    if (route === '/schedule' || route.includes('/schedule')) {
      if (req.session.user?.role === 'manager') {
        route = '/dashboard/manager/schedule';
      } else if (req.session.user?.role === 'admin') {
        route = '/dashboard/admin/schedule';
      }
    }
    
    // If description contains specific route indicators, use those to determine route
    if (description && description.includes('via manager-schedule')) {
      route = '/dashboard/manager/schedule';
    } else if (description && description.includes('via manager-assigned-resources')) {
      route = '/dashboard/manager/assigned-resources';
    } else if (description && description.includes('via manager-calendar-view')) {
      route = '/dashboard/manager/calendar-view';
    } else if (description && description.includes('via admin-')) {
      // Extract admin route from description
      const adminRouteMatch = description.match(/via (admin-[a-z-]+)/);
      if (adminRouteMatch) {
        route = `/dashboard/admin/${adminRouteMatch[1]}`;
      }
    }
    
    // Get employee and project names for better description
    let employeeCode = '', employeeName = '', projectName = '';
    
    // Handle bulk operations differently
    if (action === 'bulk_assign' || action === 'bulk_replace' || 
        (changes && (changes.operation === 'admin_bulk_schedule_assignment_multiple_projects' || 
                     changes.operation === 'admin_schedule_assignment_single_project_multiple_employees' ||
                     changes.operation === 'manager_bulk_schedule_assignment_multiple_projects' ||
                     changes.operation === 'manager_schedule_assignment_single_project_multiple_employees'))) {
      
      // For bulk operations, try to get info from changes object
      if (changes.sourceEmployee) {
        employeeCode = changes.sourceEmployee;
        const sourceEmployee = await Employee.findOne({ empCode: changes.sourceEmployee });
        if (sourceEmployee) {
          employeeName = sourceEmployee.name;
        }
      }
      
      // For our consolidated operations, get employee info from changes
      if (changes.employeeDetails) {
        if (Array.isArray(changes.employeeDetails)) {
          // Multiple employees - use the first one for the main fields, and create a summary
          if (changes.employeeDetails.length > 0) {
            employeeCode = changes.employeeDetails[0].empCode;
            employeeName = changes.employeeDetails[0].name;
            // If there are multiple employees, create a summary format
            if (changes.employeeDetails.length > 1) {
              const employeeCodes = changes.employeeDetails.map(e => e.empCode).join(', ');
              const employeeNames = changes.employeeDetails.map(e => e.name).join(', ');
              employeeCode = `${changes.employeeDetails.length} employees: ${employeeCodes}`;
              employeeName = employeeNames;
            }
          }
        } else {
          // Single employee object
          employeeCode = changes.employeeDetails.empCode;
          employeeName = changes.employeeDetails.name;
        }
      }
      
      // For bulk operations, project name might be in the changes
      if (changes.sourceProjects && changes.sourceProjects.length > 0) {
        // Handle multiple projects by creating a comma-separated list
        const projectNames = [];
        for (const sourceProject of changes.sourceProjects) {
          if (sourceProject.projectName) {
            projectNames.push(sourceProject.projectName);
          } else if (sourceProject.projectId) {
            const projectDoc = await ProjectMaster.findById(sourceProject.projectId);
            if (projectDoc) {
              projectNames.push(projectDoc.projectName);
            }
          }
        }
        // Join all project names with commas, or use the first one if only one project
        projectName = projectNames.length > 1 ? projectNames.join(', ') : (projectNames[0] || '');
      }
      
      // For our consolidated operations, get project info from changes
      if (changes.projectDetails) {
        if (Array.isArray(changes.projectDetails)) {
          // Multiple projects
          projectName = changes.projectDetails.map(p => p.projectName).join(', ');
        } else if (changes.projectDetails.projectName) {
          // Single project
          projectName = changes.projectDetails.projectName;
        }
      }
    } else {
      // Regular operations - use the existing logic
      if (before?.employee || after?.employee) {
        const employeeDoc = await Employee.findById(before?.employee || after?.employee);
        if (employeeDoc) {
          employeeCode = employeeDoc.empCode;
          employeeName = employeeDoc.name;
        }
      }
      
      if (before?.project || after?.project) {
        const projectDoc = await ProjectMaster.findById(before?.project || after?.project);
        if (projectDoc) {
          projectName = projectDoc.projectName;
        }
      }
    }

    // Create detailed description of changes
    let detailedDescription = description;
    if (action === 'update' && before && after) {
      const changeDetails = [];
      
      // Check daily hours changes
      if (before.dailyHours && after.dailyHours) {
        const beforeHours = before.dailyHours;
        const afterHours = after.dailyHours;
        
        // Find changed dates
        const allDates = new Set([...Object.keys(beforeHours), ...Object.keys(afterHours)]);
        
        for (const date of allDates) {
          const beforeVal = beforeHours[date] || 0;
          const afterVal = afterHours[date] || 0;
          
          if (beforeVal !== afterVal) {
            changeDetails.push(`${date}: ${beforeVal}h → ${afterVal}h`);
          }
        }
      }
      
      // Check project changes
      if (before.project?.toString() !== after.project?.toString()) {
        const beforeProject = await ProjectMaster.findById(before.project);
        const afterProject = await ProjectMaster.findById(after.project);
        changeDetails.push(`Project: ${beforeProject?.projectName || 'Unknown'} → ${afterProject?.projectName || 'Unknown'}`);
      }
      
      if (changeDetails.length > 0) {
        detailedDescription += ` | Changes: ${changeDetails.join(', ')}`;
      }
    }

    const auditEntry = await AuditLog.create({
      manager: userEmail,
      managerName: userName,
      userRole: userRole,
      action,
      assignmentId,
      employeeCode,
      employeeName,
      projectName,
      description: detailedDescription,
      changes,
      before,
      after,
      route,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      timestamp: new Date()
    });
    
    // console.log('✅ Audit log created successfully:', auditEntry._id);
    // console.log('✅ Final description:', detailedDescription);
  } catch (err) {
    console.error('❌ Audit logging error:', err);
  }
}

// Function to revert changes (admin only)
async function revertAuditLog(auditLogId, adminEmail, reason) {
  try {
    const auditLog = await AuditLog.findById(auditLogId);
    if (!auditLog) {
      throw new Error('Audit log not found');
    }
    
    if (auditLog.isReverted) {
      throw new Error('Audit log has already been reverted');
    }

    // Only allow reverting certain actions
    if (!['create', 'update', 'delete'].includes(auditLog.action)) {
      throw new Error('This type of action cannot be reverted');
    }

    // Only allow reverting if there's assignment data
    if (!auditLog.assignmentId) {
      throw new Error('Cannot revert: No assignment ID found');
    }

    // Revert the actual assignment change
    if (auditLog.assignmentId && auditLog.before) {
      if (auditLog.action === 'delete') {
        // Recreate the deleted assignment
        await AssignedSchedule.create(auditLog.before);
      } else if (auditLog.action === 'create') {
        // Delete the created assignment
        await AssignedSchedule.findByIdAndDelete(auditLog.assignmentId);
      } else if (auditLog.action === 'update') {
        // Restore previous state
        await AssignedSchedule.findByIdAndUpdate(auditLog.assignmentId, auditLog.before);
      }
    }

    // Mark audit log as reverted
    auditLog.isReverted = true;
    auditLog.revertedBy = adminEmail;
    auditLog.revertedAt = new Date();
    auditLog.revertReason = reason;
    await auditLog.save();

    // Create a new audit log entry for the revert action
    await AuditLog.create({
      manager: adminEmail,
      managerName: adminEmail.split('@')[0],
      userRole: 'admin',
      action: 'delete', // revert is essentially a delete/undo action
      assignmentId: auditLog.assignmentId,
      employeeCode: auditLog.employeeCode,
      employeeName: auditLog.employeeName,
      projectName: auditLog.projectName,
      description: `Admin ${adminEmail} reverted ${auditLog.action} action by ${auditLog.manager}. Reason: ${reason}`,
      changes: {
        operation: 'admin_revert_action',
        originalAuditId: auditLogId,
        originalAction: auditLog.action,
        originalManager: auditLog.manager,
        revertReason: reason
      },
      before: auditLog.after, // what was there before revert
      after: auditLog.before, // what it becomes after revert
      route: '/audit-logs',
      timestamp: new Date()
    });

    return { success: true, message: 'Changes reverted successfully' };
  } catch (err) {
    console.error('Revert error:', err);
    return { success: false, error: err.message };
  }
}


// mongoose.connect('mongodb://127.0.0.1:27017/hrms-app', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// }).then(() => console.log('✅ MongoDB connected'))
//   .catch(err => console.error('❌ MongoDB error:', err));

const mongoURI = process.env.MONGODB_URI;

mongoose.connect(process.env.MONGODB_URI).then(() => {
  console.log('Connected to MongoDB atlas successfully');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});


const app = express();
const port = 3000;
app.use(express.json());

// Dummy Users
const users = [
  {
    email: 'admin@cbsl.com',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin'
  }
  // {
  //   email: 'manager.DIH@cbsl.com',
  //   password: bcrypt.hashSync('123', 10),
  //   role: 'manager'
  // },
  // {
  //   email: 'manager.ABC@cbsl.com',
  //   password: bcrypt.hashSync('abc123', 10),
  //   role: 'manager'
  // },
  // {
  //   email: 'manager.XYZ@cbsl.com',
  //   password: bcrypt.hashSync('xyz123', 10),
  //   role: 'manager'
  // },
  // {
  //   email: 'manager.PQR@cbsl.com',
  //   password: bcrypt.hashSync('pqr123', 10),
  //   role: 'manager'
  // }
];

// Multer for uploads
const upload = multer({ dest: 'uploads/' });

// EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
const expressLayouts = require('express-ejs-layouts');
app.use(expressLayouts);
app.set('layout', 'sidebar-layout');

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Session
app.use(session({
  secret: 'mySecretKey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// CSRF
const csrfProtection = csrf({ cookie: false });

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.log('CSRF Token Error:', {
      received: req.body._csrf,
      session: req.session.csrfSecret
    });
    return res.status(403).send('Invalid CSRF token');
  }
  next(err);
});

// Auth Middleware
function isAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.user?.role === 'admin') return next();
  res.status(403).render('error', { 
    message: 'Access denied: Only administrators can access this page.',
    layout: false,
    title: 'Access Denied',
    user: req.session.user
  });
}

function isManager(req, res, next) {
  if (req.session.user?.role === 'manager') return next();
  res.status(403).render('error', { 
    message: 'Access denied: Only managers can access this page.',
    layout: false,
    title: 'Access Denied',
    user: req.session.user
  });
}

// Login Routes

app.get('/', (req, res) => {
  res.redirect('login');
});

app.get('/login', csrfProtection, (req, res) => {
  res.render('login', {
    title: 'Login',
    messages: [],
    hasErrors: false,
    csrfToken: req.csrfToken(),
    layout: false
  });
});

app.post('/login', csrfProtection, async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // Try MongoDB first
    let user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = {
        id: user._id,
        email: user.email,
        role: user.role
      };
      if (user.role === 'manager') return res.redirect('/dashboard/manager');
      if (user.role === 'admin') return res.redirect('/dashboard/admin');
      return res.status(403).send('Unauthorized role');
    }

    // If not found in DB, check dummy array
    const dummyUser = users.find(u => u.email === email && bcrypt.compareSync(password, u.password));
    if (dummyUser) {
      req.session.user = {
        email: dummyUser.email,
        role: dummyUser.role
      };
      if (dummyUser.role === 'manager') return res.redirect('/dashboard/manager');
      if (dummyUser.role === 'admin') return res.redirect('/dashboard/admin');
      return res.status(403).send('Unauthorized role');
    }

    // If neither found
    return res.render('login', {
      title: 'Login',
      messages: ['Invalid credentials'],
      hasErrors: true,
      layout: false,
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.render('login', {
      title: 'Login',
      messages: ['An error occurred during login'],
      hasErrors: true,
      layout: false,
      csrfToken: req.csrfToken()
    });
  }
});

// Dashboards

// Manager Dashboard with sidebar (only Schedule & Assigned Resources)
app.get('/dashboard/manager', isAuth, isManager, (req, res) => {
  res.render('manager-welcome', {
    title: 'Manager Dashboard',
    layout: 'sidebar-layout',
    manager: true // flag for sidebar rendering
  });
});


// Manager Calendar Route
app.get('/dashboard/manager/calendar-view', isAuth, isManager, (req, res) => {
    // Manager Calendar View: fetch and pass all required data
  (async () => {
    try {
      // Support month range selection
      const startMonthParam = req.query.startMonth;
      const endMonthParam = req.query.endMonth;

      let startYear, startMonth, endYear, endMonth;
      if (startMonthParam && endMonthParam) {
        const startParts = startMonthParam.split('-');
        const endParts = endMonthParam.split('-');
        startYear = parseInt(startParts[0], 10);
        startMonth = parseInt(startParts[1], 10);
        endYear = parseInt(endParts[0], 10);
        endMonth = parseInt(endParts[1], 10);
      } else {
        const now = new Date();
        startYear = now.getFullYear();
        startMonth = now.getMonth() + 1;
        endYear = now.getFullYear();
        endMonth = now.getMonth() + 1;
      }

      // Get all schedules (optionally, you can filter by manager's employees/projects if needed)
      const allSchedules = await AssignedSchedule.find()
        .populate('employee')
        .populate('project');

      // Generate dateRange for all working days between start and end month
      const dateRange = [];
      let currentYear = startYear;
      let currentMonth = startMonth;
      while (currentYear < endYear || (currentYear === endYear && currentMonth <= endMonth)) {
        const daysInMonth = new Date(currentYear, currentMonth, 0).getDate();
        for (let d = 1; d <= daysInMonth; d++) {
          const dateObj = new Date(currentYear, currentMonth - 1, d);
          // Include all days (no skipping weekends)
          const day = dateObj.getDate();
          const monthName = dateObj.toLocaleString('default', { month: 'short' });
          dateRange.push(`${day}-${monthName}-${currentYear}`);
        }
        if (currentMonth === 12) {
          currentMonth = 1;
          currentYear++;
        } else {
          currentMonth++;
        }
      }

      // Get all employees
const allEmployees = await Employee.find({}, 'empCode name division designation homePractice practiceManager');
      // Build empDayProjects: { empCode: { date: [ { projectName, hours } ] } }
      const empDayProjects = {};
      allSchedules.forEach(s => {
        const empCode = s.employee?.empCode || 'N/A';
        if (!empDayProjects[empCode]) empDayProjects[empCode] = {};
        if (s.dailyHours && s.project && s.project.projectName) {
          Object.keys(s.dailyHours).forEach(dateKey => {
            if (!empDayProjects[empCode][dateKey]) empDayProjects[empCode][dateKey] = [];
            empDayProjects[empCode][dateKey].push({
              projectName: s.project.projectName,
              projectId: s.project._id,
              assignmentId: s._id,
              hours: Number(s.dailyHours[dateKey]) || 0
            });
          });
        }
      });

      res.render('manager-calendar-view', {
        startYear,
        startMonth,
        endYear,
        endMonth,
        dateRange,
        allEmployees,
        empDayProjects,
        layout: 'sidebar-layout',
        title: 'Manager Calendar View',
        manager: true
      });
    } catch (err) {
      console.error('Error loading manager calendar view:', err);
      res.status(500).send('Internal Server Error');
    }
  })();
});

// Manager: Schedule page

app.get('/dashboard/manager/schedule', isAuth, isManager, async (req, res) => {
  try {
    const employees = await Employee.find();
    const projects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient');
    // Get unique home practices from employees
    const practices = [...new Set(employees.map(emp => emp.homePractice).filter(Boolean))];
    res.render('manager-schedule', {
      employees,
      projects,
      practices,
      csrfToken: req.csrfToken ? req.csrfToken() : '',
      title: 'Manager Schedule',
      layout: 'sidebar-layout',
      manager: true
    });
  } catch (err) {
    console.error('Error loading manager schedule page:', err);
    res.status(500).send('Internal Server Error');
  }
});
app.post('/assigned-resources/add', isAuth, isAdmin, async (req, res) => {
  try {
    const { employee, project, dailyHours } = req.body;
    // Validation
    if (!employee || !project) {
      return res.status(400).json({ success: false, error: 'Employee and Project are required.' });
    }
    if (!dailyHours || typeof dailyHours !== 'object' || Object.keys(dailyHours).length === 0) {
      return res.status(400).json({ success: false, error: 'At least one daily hour entry is required.' });
    }
    // Validate daily hours: all values must be 0-8
    for (const key in dailyHours) {
      const val = Number(dailyHours[key]);
      if (isNaN(val) || val < 0 || val > 8) {
        return res.status(400).json({ success: false, error: `Invalid hours for ${key}: must be 0-8.` });
      }
    }
    // Check employee and project exist
    const employeeDoc = await Employee.findById(employee);
    const projectDoc = await ProjectMaster.findById(project);
    if (!employeeDoc || !projectDoc) {
      return res.status(400).json({ success: false, error: 'Employee or Project not found.' });
    }
    // Check for existing schedule for this employee/project
    let existingSchedule = await AssignedSchedule.findOne({ employee, project });
    if (existingSchedule) {
      // Store original for audit logging
      const originalSchedule = existingSchedule.toObject();
      
      // Merge/overwrite dailyHours
      existingSchedule.dailyHours = { ...existingSchedule.dailyHours, ...dailyHours };
      await existingSchedule.save();
      
      // Admin audit logging for update
      const description = `Admin ${req.session.user?.email} updated assignment for ${employeeDoc.empCode} (${employeeDoc.name}) on project ${projectDoc.projectName} via admin-assigned-resources-add`;
      const changes = {
        operation: 'admin_update_assignment',
        employeeDetails: { empCode: employeeDoc.empCode, name: employeeDoc.name },
        projectDetails: { projectName: projectDoc.projectName },
        dailyHours: dailyHours
      };
      await logAuditAction(req, 'update', existingSchedule._id, originalSchedule, existingSchedule.toObject(), description, changes);
      
      return res.status(200).json({ success: true, schedule: existingSchedule, updated: true });
    } else {
      const newSchedule = new AssignedSchedule({
        employee,
        project,
        dailyHours
      });
      await newSchedule.save();
      
      // Admin audit logging for creation
      const description = `Admin ${req.session.user?.email} created assignment for ${employeeDoc.empCode} (${employeeDoc.name}) on project ${projectDoc.projectName} via admin-assigned-resources-add`;
      const changes = {
        operation: 'admin_create_assignment',
        employeeDetails: { empCode: employeeDoc.empCode, name: employeeDoc.name },
        projectDetails: { projectName: projectDoc.projectName },
        dailyHours: dailyHours
      };
      await logAuditAction(req, 'create', newSchedule._id, null, newSchedule.toObject(), description, changes);
      
      return res.status(201).json({ success: true, schedule: newSchedule, created: true });
    }
  } catch (err) {
    console.error('Error in POST /assigned-resources/add:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Manager: Assigned Resources page
// Manager: Update assigned schedule (PUT)
app.put('/dashboard/manager/assigned-resources/:id', isAuth, isManager, async (req, res) => {
  try {
    const scheduleId = req.params.id;
    const updateFields = {};
    // Project name (optional)
    let projectName = req.body['project[projectName]'] || (req.body.project && req.body.project.projectName);
    if (projectName) {
      const projectDoc = await ProjectMaster.findOne({ projectName: projectName });
      if (projectDoc) {
        updateFields['project'] = projectDoc._id;
      }
    }
    // Daily hours
    let dailyHoursObj = {};
    if (req.body.dailyHours) {
      Object.keys(req.body.dailyHours).forEach(dateKey => {
        dailyHoursObj[dateKey] = Number(req.body.dailyHours[dateKey]) || 0;
      });
      updateFields['dailyHours'] = dailyHoursObj;
    }
    // Get original schedule for audit logging
    const originalSchedule = await AssignedSchedule.findById(scheduleId).populate('employee').populate('project');
    
    const updated = await AssignedSchedule.findByIdAndUpdate(
      scheduleId,
      { $set: updateFields },
      { new: true }
    ).populate('employee').populate('project');
    
    if (updated) {
      // Audit logging for manager update
      const changes = {
        projectName: projectName || 'No change',
        dailyHours: dailyHoursObj,
        updatedFields: updateFields
      };
      
      // Create more detailed description
      let changeDescription = `${getUserRolePrefix(req)} updated assignment for ${originalSchedule?.employee?.empCode || 'Unknown'} on project ${originalSchedule?.project?.projectName || 'Unknown'} via ${getRouteContext(req)}`;
      
      await logAuditAction(req, 'update', scheduleId, originalSchedule?.toObject(), updated.toObject(), changeDescription, changes);
      
      res.json({ success: true, schedule: updated });
    } else {
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Manager PUT error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Manager: Delete assigned schedule (DELETE)
app.delete('/dashboard/manager/assigned-resources/:id', isAuth, isManager, async (req, res) => {
  try {
    const scheduleId = req.params.id;
    
    // Get original schedule for audit logging before deletion
    const originalSchedule = await AssignedSchedule.findById(scheduleId).populate('employee').populate('project');
    
    const result = await AssignedSchedule.deleteOne({ _id: scheduleId });
    if (result.deletedCount > 0) {
      // Audit logging for manager delete
      const description = `${getUserRolePrefix(req)} deleted assignment for ${originalSchedule?.employee?.empCode || 'Unknown'} on project ${originalSchedule?.project?.projectName || 'Unknown'} via ${getRouteContext(req)}`;
      await logAuditAction(req, 'delete', scheduleId, originalSchedule?.toObject(), null, description);
      
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Manager DELETE error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Manager: Bulk delete assigned schedules
app.post('/dashboard/manager/assigned-resources/bulk-delete', isAuth, isManager, async (req, res) => {
  try {
    const ids = req.body['ids[]'] || req.body.ids || req.body.scheduleIds;
    
    if (!ids) {
      return res.status(400).json({ success: false, error: 'No schedule IDs provided' });
    }
    
    // Ensure ids is always an array
    const idsArray = Array.isArray(ids) ? ids : [ids];
    
    if (idsArray.length === 0) {
      return res.status(400).json({ success: false, error: 'No schedule IDs provided' });
    }
    
    // Get original schedules for audit logging before deletion
    const originalSchedules = await AssignedSchedule.find({ _id: { $in: idsArray } }).populate('employee').populate('project');
    
    // Delete the schedules
    const result = await AssignedSchedule.deleteMany({ _id: { $in: idsArray } });
    
    if (result.deletedCount > 0) {
      // Create consolidated audit log for bulk deletion
      const deletedSchedulesInfo = originalSchedules.map(s => ({
        empCode: s.employee?.empCode || 'N/A',
        empName: s.employee?.name || 'N/A',
        projectName: s.project?.projectName || 'N/A',
        assignmentId: s._id
      }));
      
      const employeeNames = deletedSchedulesInfo.map(s => `${s.empCode} (${s.empName})`).join(', ');
      const projectNames = [...new Set(deletedSchedulesInfo.map(s => s.projectName))].join(', ');
      
      const description = `${getUserRolePrefix(req)} bulk deleted ${result.deletedCount} assignments for employees: ${employeeNames} from projects: ${projectNames} via ${getRouteContext(req)}`;
      
      const changes = {
        operation: 'manager_bulk_delete_assignments',
        deletedCount: result.deletedCount,
        deletedSchedules: deletedSchedulesInfo,
        employeeCount: [...new Set(deletedSchedulesInfo.map(s => s.empCode))].length,
        projectCount: [...new Set(deletedSchedulesInfo.map(s => s.projectName))].length
      };
      
      // For bulk operations, use the first employee and project info for the main fields
      const firstEmployee = originalSchedules[0]?.employee;
      const firstProject = originalSchedules[0]?.project;
      
      // Create a custom audit log entry that populates the Employee and Project columns properly
      const auditEntry = await AuditLog.create({
        manager: req.session.user?.email || 'Unknown',
        managerName: req.session.user?.email?.split('@')[0] || 'Unknown',
        userRole: req.session.user?.role || 'manager',
        action: 'delete',
        assignmentId: originalSchedules[0]?._id,
        employeeCode: result.deletedCount === 1 ? firstEmployee?.empCode : `${result.deletedCount} employees`,
        employeeName: result.deletedCount === 1 ? firstEmployee?.name : employeeNames,
        projectName: [...new Set(deletedSchedulesInfo.map(s => s.projectName))].length === 1 ? 
                    deletedSchedulesInfo[0].projectName : 
                    `${[...new Set(deletedSchedulesInfo.map(s => s.projectName))].length} projects`,
        description: description,
        changes: changes,
        before: { bulk: true, schedules: originalSchedules.map(s => s.toObject()) },
        after: null,
        route: req.originalUrl || getRouteContext(req),
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()
      });
      
      res.json({ success: true, message: `Successfully deleted ${result.deletedCount} schedule(s)` });
    } else {
      res.status(404).json({ success: false, error: 'No schedules found or already deleted' });
    }
  } catch (err) {
    console.error('Error in manager bulk delete assigned-resources:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/dashboard/manager/assigned-resources', isAuth, isManager, async (req, res) => {
  try {
    // Get filter params
    const employeeFilter = req.query.employee || '';
    const projectFilter = req.query.project || '';
    const fromMonthFilter = req.query.fromMonth || '';
    const toMonthFilter = req.query.toMonth || '';

    // Fetch schedules with populated employee and project data
    const schedules = await AssignedSchedule.find()
      .populate('employee')
      .populate('project');

    // Build query for AssignedSchedule
    let scheduleQuery = {};
    if (employeeFilter) {
      const empDoc = await Employee.findOne({ empCode: employeeFilter });
      if (empDoc) scheduleQuery.employee = empDoc._id;
    }
    if (projectFilter) {
      const projDoc = await ProjectMaster.findOne({ projectName: projectFilter });
      if (projDoc) scheduleQuery.project = projDoc._id;
    }

    // Only show one schedule per employee/project (latest)
    const allSchedules = await AssignedSchedule.find(scheduleQuery)
      .populate('employee')
      .populate('project')
      .populate('practice');
    const latestSchedules = {};
    for (const s of allSchedules) {
      const empId = s.employee?._id ? s.employee._id.toString() : String(s.employee);
      const projId = s.project?._id ? s.project._id.toString() : String(s.project);
      const key = `${empId}-${projId}`;
      if (!latestSchedules[key] || (s._id > latestSchedules[key]._id)) {
        latestSchedules[key] = s;
      }
    }
    const uniqueSchedules = Object.values(latestSchedules);

    // Generate dateRange for the selected month range (or current month if not selected)
    let startYear, startMonth, endYear, endMonth;
    if (fromMonthFilter && toMonthFilter) {
      // fromMonthFilter and toMonthFilter format: 'YYYY-MM'
      const fromParts = fromMonthFilter.split('-');
      const toParts = toMonthFilter.split('-');
      startYear = parseInt(fromParts[0], 10);
      startMonth = parseInt(fromParts[1], 10) - 1; // JS months are 0-indexed
      endYear = parseInt(toParts[0], 10);
      endMonth = parseInt(toParts[1], 10) - 1;
    } else if (fromMonthFilter) {
      const fromParts = fromMonthFilter.split('-');
      startYear = endYear = parseInt(fromParts[0], 10);
      startMonth = endMonth = parseInt(fromParts[1], 10) - 1;
    } else if (toMonthFilter) {
      const toParts = toMonthFilter.split('-');
      startYear = endYear = parseInt(toParts[0], 10);
      startMonth = endMonth = parseInt(toParts[1], 10) - 1;
    } else {
      const now = new Date();
      startYear = endYear = now.getFullYear();
      startMonth = endMonth = now.getMonth();
    }
    // Generate all dates between start and end month (inclusive)
    const dateRange = [];
    let currentYear = startYear;
    let currentMonth = startMonth;
    while (currentYear < endYear || (currentYear === endYear && currentMonth <= endMonth)) {
      const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
      for (let d = 1; d <= daysInMonth; d++) {
        const dateObj = new Date(currentYear, currentMonth, d);
        const day = dateObj.getDate();
        const monthName = dateObj.toLocaleString('default', { month: 'short' });
        const year = dateObj.getFullYear();
        dateRange.push(`${day}-${monthName}-${year}`);
      }
      currentMonth++;
      if (currentMonth > 11) {
        currentMonth = 0;
        currentYear++;
      }
    }

    // Generate all dates for current year (YYYY-MM-DD)
    const allYearDates = [];
    let minDate = new Date(startYear + '-01-01');
    let maxDate = new Date(endYear + '-12-31');
    for (let d = new Date(minDate); d <= maxDate; d.setDate(d.getDate() + 1)) {
      let dateStr = d.toISOString().slice(0,10);
      allYearDates.push(dateStr);
    }

    // Get all employees and projects for filter dropdowns
    const allEmployees = await Employee.find({}, 'empCode name division designation');
    const allProjects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient');

    res.render('manager-assigned-resources', {
      schedules: uniqueSchedules,
      dateRange,
      allYearDates,
      allEmployees,
      allProjects,
      employeeFilter,
      projectFilter,
      fromMonthFilter,
      toMonthFilter,
      errorMessage: req.query.error || '',
      layout: 'sidebar-layout',
      title: 'Manager Assigned Resources',
      manager: true
    });
  } catch (err) {
    console.error('Error loading manager assigned resources page:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/dashboard/manager/schedule', isAuth, isManager, async (req, res) => {
  try {
    const empCodes = Array.isArray(req.body.emp_ids) ? req.body.emp_ids : [req.body.emp_ids];
    const filteredEmpCodes = empCodes.filter(code => code?.trim());
    const startDate = new Date(req.body.start_date);
    const endDate = new Date(req.body.end_date);

    // Validate dates
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).send('Invalid start or end date. Please select valid dates.');
    }
    if (endDate < startDate) {
      return res.status(400).send('End date must be after start date.');
    }

    function getDateKeysSkipWeekends(start, end) {
      const keys = [];
      let d = new Date(start);
      while (d <= end) {
        const dayOfWeek = d.getDay();
        if (dayOfWeek !== 0 && dayOfWeek !== 6) {
          const dateStr = d.toISOString().slice(0,10);
          keys.push({ key: dateStr, dateObj: new Date(d) });
        }
        d.setDate(d.getDate() + 1);
      }
      return keys;
    }
    const dateKeys = getDateKeysSkipWeekends(startDate, endDate);

    function formatDateKey(dateStr) {
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        const year = d.getFullYear();
        return `${day}-${monthName}-${year}`;
      }
      return dateStr;
    }

    // Check if we have project arrays (multiple projects)
    const projectIds = req.body['project_ids[]'] ? (Array.isArray(req.body['project_ids[]']) ? req.body['project_ids[]'] : [req.body['project_ids[]']]) : [];
    const hoursList = req.body['hours_list[]'] ? (Array.isArray(req.body['hours_list[]']) ? req.body['hours_list[]'] : [req.body['hours_list[]']]) : [];
    
    // Check if we have single project fields
    const singleProjectId = req.body.project_id;
    const singleHours = req.body.hours;

    // Determine which path to take
    if (projectIds.length > 0 && hoursList.length > 0 && projectIds.length === hoursList.length) {
      console.log('🔍 Taking Path 1: Multiple projects assignment', { 
        projectCount: projectIds.length, 
        employeeCount: filteredEmpCodes.length 
      });
      // Path 1: Multiple projects assignment (works for both single and multiple employees)
      
      // Check if this is multiple employees → single project (consolidation needed)
      if (projectIds.length === 1 && filteredEmpCodes.length > 1) {
        // Multiple employees → Single project - create consolidated audit log
        const projectId = projectIds[0];
        const hours = Number(hoursList[0]) || 0;
        let employeeAudits = [];
        let assignmentIds = [];
        
        for (const empCode of filteredEmpCodes) {
          const employee = await Employee.findOne({ empCode });
          if (!employee) {
            console.warn('Employee not found:', empCode);
            continue;
          }
          
          // Over-allocation check
          let overAllocated = false;
          let overAllocDetails = [];
          for (const { key: dateKey, dateObj } of dateKeys) {
            let newTotal = hours;
            let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
            let existingTotal = 0;
            for (const sched of existingSchedules) {
              let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
              existingTotal += Number(dh) || 0;
            }
            let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectId });
            if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
              existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
            }
            let totalHours = existingTotal + newTotal;
            if (totalHours > 8) {
              overAllocated = true;
              overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
            }
          }
          if (overAllocated) {
            return res.redirect(`/dashboard/manager/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
          }
          
          // Save assignment
          const query = { employee: employee._id, project: projectId };
          let existingSchedule = await AssignedSchedule.findOne(query);
          let dailyHoursObj = {};
          if (existingSchedule && existingSchedule.dailyHours) {
            dailyHoursObj = { ...existingSchedule.dailyHours };
          }
          for (const { key: dateKey, dateObj } of dateKeys) {
            dailyHoursObj[formatDateKey(dateKey)] = hours;
          }
          
          const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
          const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
            $setOnInsert: { employee: employee._id, project: projectId },
            $set: { dailyHours: dailyHoursObj, startDate, endDate },
          }, { upsert: true, new: true });
          
          // Collect employee information for consolidated audit log
          employeeAudits.push({
            empCode: empCode,
            name: employee.name,
            action: existingSchedule ? 'updated' : 'created',
            previousSchedule: previousSchedule,
            updatedSchedule: updatedSchedule.toObject(),
            assignmentId: updatedSchedule._id
          });
          assignmentIds.push(updatedSchedule._id);
        }
        
        // Create consolidated audit log for all employees assigned to this project
        if (employeeAudits.length > 0) {
          const projectDoc = await ProjectMaster.findById(projectId);
          const employeeNames = employeeAudits.map(e => `${e.empCode} (${e.name})`).join(', ');
          const hasUpdates = employeeAudits.some(e => e.action === 'updated');
          const hasCreates = employeeAudits.some(e => e.action === 'created');
          
          let actionDescription = '';
          let auditAction = '';
          if (hasUpdates && hasCreates) {
            actionDescription = 'created/updated';
            auditAction = 'bulk_assign';
          } else if (hasUpdates) {
            actionDescription = 'updated';
            auditAction = 'update';
          } else {
            actionDescription = 'created';
            auditAction = 'create';
          }
          
          const description = `${getUserRolePrefix(req)} ${actionDescription} assignment for ${employeeAudits.length} employees (${employeeNames}) on project ${projectDoc?.projectName || 'Unknown'} from ${startDate.toDateString()} to ${endDate.toDateString()} via ${getRouteContext(req)}`;
          
          const changes = {
            operation: 'manager_schedule_assignment_single_project_multiple_employees',
            projectDetails: { projectName: projectDoc?.projectName || 'Unknown' },
            employeesCount: employeeAudits.length,
            employeeDetails: employeeAudits.map(e => ({ empCode: e.empCode, name: e.name, action: e.action })),
            hours: hours,
            dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
            assignmentIds: assignmentIds
          };
          
          await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
        }
      } else {
        // Single employee → Multiple projects OR Multiple employees → Multiple projects
        for (const empCode of filteredEmpCodes) {
          const employee = await Employee.findOne({ empCode });
          if (!employee) {
            console.warn('Employee not found:', empCode);
            continue;
          }
          
          // Over-allocation check
          let overAllocated = false;
          let overAllocDetails = [];
          for (const { key: dateKey, dateObj } of dateKeys) {
            let newTotal = 0;
            for (let i = 0; i < projectIds.length; i++) {
              newTotal += Number(hoursList[i]) || 0;
            }
            let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
            let existingTotal = 0;
            for (const sched of existingSchedules) {
              let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
              existingTotal += Number(dh) || 0;
            }
            for (let i = 0; i < projectIds.length; i++) {
              let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectIds[i] });
              if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
                existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
              }
            }
            let totalHours = existingTotal + newTotal;
            if (totalHours > 8) {
              overAllocated = true;
              overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
            }
          }
          if (overAllocated) {
            return res.redirect(`/dashboard/manager/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
          }
          
          // For single employee → multiple projects, consolidate audit logs
          if (projectIds.length > 1 && filteredEmpCodes.length === 1) {
            // Save for each project and collect audit information
            let projectAudits = [];
            let assignmentIds = [];
            
            for (let i = 0; i < projectIds.length; i++) {
              const projectId = projectIds[i];
              const hours = Number(hoursList[i]) || 0;
              const query = { employee: employee._id, project: projectId };
              let existingSchedule = await AssignedSchedule.findOne(query);
              let dailyHoursObj = {};
              if (existingSchedule && existingSchedule.dailyHours) {
                dailyHoursObj = { ...existingSchedule.dailyHours };
              }
              for (const { key: dateKey, dateObj } of dateKeys) {
                dailyHoursObj[formatDateKey(dateKey)] = hours;
              }
              
              const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
              const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
                $setOnInsert: { employee: employee._id, project: projectId },
                $set: { dailyHours: dailyHoursObj, startDate, endDate },
              }, { upsert: true, new: true });
              
              // Collect project information for consolidated audit log
              const projectDoc = await ProjectMaster.findById(projectId);
              projectAudits.push({
                projectName: projectDoc?.projectName || 'Unknown',
                hours: hours,
                action: existingSchedule ? 'updated' : 'created',
                previousSchedule: previousSchedule,
                updatedSchedule: updatedSchedule.toObject(),
                assignmentId: updatedSchedule._id
              });
              assignmentIds.push(updatedSchedule._id);
            }
            
            // Create consolidated audit log for all projects assigned to this employee
            if (projectAudits.length > 0) {
              const projectNames = projectAudits.map(p => p.projectName).join(', ');
              const totalHours = projectAudits.reduce((sum, p) => sum + p.hours, 0);
              const hasUpdates = projectAudits.some(p => p.action === 'updated');
              const hasCreates = projectAudits.some(p => p.action === 'created');
              
              let actionDescription = '';
              let auditAction = '';
              if (hasUpdates && hasCreates) {
                actionDescription = 'created/updated';
                auditAction = 'bulk_assign';
              } else if (hasUpdates) {
                actionDescription = 'updated';
                auditAction = 'update';
              } else {
                actionDescription = 'created';
                auditAction = 'create';
              }
              
              const description = `${getUserRolePrefix(req)} ${actionDescription} assignment for ${empCode} on ${projectAudits.length} projects (${projectNames}) from ${startDate.toDateString()} to ${endDate.toDateString()} via ${getRouteContext(req)}`;
              
              const changes = {
                operation: 'manager_bulk_schedule_assignment_multiple_projects',
                employeeDetails: { empCode: empCode, name: employee.name },
                projectsCount: projectAudits.length,
                projectDetails: projectAudits.map(p => ({ projectName: p.projectName, hours: p.hours, action: p.action })),
                totalHours: totalHours,
                dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
                assignmentIds: assignmentIds
              };
              
              await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
            }
          } else {
            // Multiple employees → Multiple projects: create consolidated audit logs per employee
            // Save for each project and collect audit information for consolidated log per employee
            let projectAudits = [];
            let assignmentIds = [];
            
            for (let i = 0; i < projectIds.length; i++) {
              const projectId = projectIds[i];
              const hours = Number(hoursList[i]) || 0;
              const query = { employee: employee._id, project: projectId };
              let existingSchedule = await AssignedSchedule.findOne(query);
              let dailyHoursObj = {};
              if (existingSchedule && existingSchedule.dailyHours) {
                dailyHoursObj = { ...existingSchedule.dailyHours };
              }
              for (const { key: dateKey, dateObj } of dateKeys) {
                dailyHoursObj[formatDateKey(dateKey)] = hours;
              }
              const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
              const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
                $setOnInsert: { employee: employee._id, project: projectId },
                $set: { dailyHours: dailyHoursObj, startDate, endDate },
              }, { upsert: true, new: true });
              
              // Collect project information for consolidated audit log
              const projectDoc = await ProjectMaster.findById(projectId);
              projectAudits.push({
                projectName: projectDoc?.projectName || 'Unknown',
                hours: hours,
                action: existingSchedule ? 'updated' : 'created',
                previousSchedule: previousSchedule,
                updatedSchedule: updatedSchedule.toObject(),
                assignmentId: updatedSchedule._id
              });
              assignmentIds.push(updatedSchedule._id);
            }
            
            // Create consolidated audit log for all projects assigned to this employee
            if (projectAudits.length > 0) {
              const projectNames = projectAudits.map(p => p.projectName).join(', ');
              const totalHours = projectAudits.reduce((sum, p) => sum + p.hours, 0);
              const hasUpdates = projectAudits.some(p => p.action === 'updated');
              const hasCreates = projectAudits.some(p => p.action === 'created');
              
              let actionDescription = '';
              let auditAction = '';
              if (hasUpdates && hasCreates) {
                actionDescription = 'created/updated';
                auditAction = 'bulk_assign';
              } else if (hasUpdates) {
                actionDescription = 'updated';
                auditAction = 'update';
              } else {
                actionDescription = 'created';
                auditAction = 'create';
              }
              
              const description = `${getUserRolePrefix(req)} ${actionDescription} assignment for ${empCode} on ${projectAudits.length} projects (${projectNames}) from ${startDate.toDateString()} to ${endDate.toDateString()} via ${getRouteContext(req)}`;
              
              const changes = {
                operation: 'manager_bulk_schedule_assignment_multiple_projects',
                employeeDetails: { empCode: empCode, name: employee.name },
                projectsCount: projectAudits.length,
                projectDetails: projectAudits.map(p => ({ projectName: p.projectName, hours: p.hours, action: p.action })),
                totalHours: totalHours,
                dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
                assignmentIds: assignmentIds
              };
              
              await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
            }
          }
        }
      }
    } else if (singleProjectId && singleHours) {
      console.log('🔍 Taking Path 2: Single project assignment to multiple employees');
      // Path 2: Single project assignment to multiple employees - create consolidated audit log
      const projectDoc = await ProjectMaster.findById(singleProjectId);
      if (!projectDoc) {
        return res.redirect(`/dashboard/manager/assigned-resources?error=${encodeURIComponent('Project not found: ' + singleProjectId)}`);
      }
      const hours = Number(singleHours) || 0;
      
      let employeeAudits = [];
      let assignmentIds = [];
      
      for (const empCode of filteredEmpCodes) {
        const employee = await Employee.findOne({ empCode });
        if (!employee) {
          console.warn('Employee not found:', empCode);
          continue;
        }
        
        // Over-allocation check
        let overAllocated = false;
        let overAllocDetails = [];
        for (const { key: dateKey, dateObj } of dateKeys) {
          let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
          let existingTotal = 0;
          for (const sched of existingSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
            existingTotal += Number(dh) || 0;
          }
          let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectDoc._id });
          if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
            existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
          }
          let totalHours = existingTotal + hours;
          if (totalHours > 8) {
            overAllocated = true;
            overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
          }
        }
        if (overAllocated) {
          return res.redirect(`/dashboard/manager/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
        }
        
        // Save assignment
        const query = { employee: employee._id, project: projectDoc._id };
        let existingSchedule = await AssignedSchedule.findOne(query);
        let dailyHoursObj = {};
        if (existingSchedule && existingSchedule.dailyHours) {
          dailyHoursObj = { ...existingSchedule.dailyHours };
        }
        for (const { key: dateKey, dateObj } of dateKeys) {
          dailyHoursObj[formatDateKey(dateKey)] = hours;
        }
        
        const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
        const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
          $setOnInsert: { employee: employee._id, project: projectDoc._id },
          $set: { dailyHours: dailyHoursObj, startDate, endDate },
        }, { upsert: true, new: true });
        
        // Collect employee information for consolidated audit log
        employeeAudits.push({
          empCode: empCode,
          name: employee.name,
          action: existingSchedule ? 'updated' : 'created',
          previousSchedule: previousSchedule,
          updatedSchedule: updatedSchedule.toObject(),
          assignmentId: updatedSchedule._id
        });
        assignmentIds.push(updatedSchedule._id);
      }
      
      // Create consolidated audit log for all employees assigned to this project
      if (employeeAudits.length > 0) {
        const employeeNames = employeeAudits.map(e => `${e.empCode} (${e.name})`).join(', ');
        const hasUpdates = employeeAudits.some(e => e.action === 'updated');
        const hasCreates = employeeAudits.some(e => e.action === 'created');
        
        let actionDescription = '';
        let auditAction = '';
        if (hasUpdates && hasCreates) {
          actionDescription = 'created/updated';
          auditAction = 'bulk_assign';
        } else if (hasUpdates) {
          actionDescription = 'updated';
          auditAction = 'update';
        } else {
          actionDescription = 'created';
          auditAction = 'create';
        }
        
        const description = `${getUserRolePrefix(req)} ${actionDescription} assignment for ${employeeAudits.length} employees (${employeeNames}) on project ${projectDoc.projectName} from ${startDate.toDateString()} to ${endDate.toDateString()} via ${getRouteContext(req)}`;
        
        const changes = {
          operation: 'manager_schedule_assignment_single_project_multiple_employees',
          projectDetails: { projectName: projectDoc.projectName },
          employeesCount: employeeAudits.length,
          employeeDetails: employeeAudits.map(e => ({ empCode: e.empCode, name: e.name, action: e.action })),
          hours: hours,
          dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
          assignmentIds: assignmentIds
        };
        
        await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
      }
    } else if (filteredEmpCodes.length === 1 && projectIds.length > 0) {
      console.log('🔍 Taking Path 3: Single employee, multiple projects');
      // Path 3: Single employee, multiple projects - create consolidated audit log
      const empCode = filteredEmpCodes[0];
      const employee = await Employee.findOne({ empCode });
      if (!employee) {
        console.warn('Employee not found:', empCode);
        return res.redirect('/dashboard/manager/calendar-view');
      }
      projectIds = Array.isArray(req.body['project_ids[]']) ? req.body['project_ids[]'] : [req.body['project_ids[]']];
      const hoursList = Array.isArray(req.body['hours_list[]']) ? req.body['hours_list[]'] : [req.body['hours_list[]']];

      let overAllocated = false;
      let overAllocDetails = [];
      for (const { key: dateKey, dateObj } of dateKeys) {
        let newTotal = 0;
        for (let i = 0; i < projectIds.length; i++) {
          newTotal += Number(hoursList[i]) || 0;
        }
        let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
        let existingTotal = 0;
        for (const sched of existingSchedules) {
          let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
          existingTotal += Number(dh) || 0;
        }
        for (let i = 0; i < projectIds.length; i++) {
          let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectIds[i] });
          if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
            existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
          }
        }
        let totalHours = existingTotal + newTotal;
        if (totalHours > 8) {
          overAllocated = true;
          overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
        }
      }
      if (overAllocated) {
        return res.redirect(`/dashboard/manager/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
      }

      // Save for each project and collect audit information for consolidated log
      let projectAudits = [];
      let assignmentIds = [];
      
      for (let i = 0; i < projectIds.length; i++) {
        const projectId = projectIds[i];
        const hours = Number(hoursList[i]) || 0;
        const query = { employee: employee._id, project: projectId };
        let existingSchedule = await AssignedSchedule.findOne(query);
        let dailyHoursObj = {};
        if (existingSchedule && existingSchedule.dailyHours) {
          dailyHoursObj = { ...existingSchedule.dailyHours };
        }
        for (const { key: dateKey, dateObj } of dateKeys) {
          dailyHoursObj[formatDateKey(dateKey)] = hours;
        }
        
        const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
        const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
          $setOnInsert: { employee: employee._id, project: projectId },
          $set: { dailyHours: dailyHoursObj, startDate, endDate },
        }, { upsert: true, new: true });

        // Collect project information for consolidated audit log
        const projectDoc = await ProjectMaster.findById(projectId);
        projectAudits.push({
          projectName: projectDoc?.projectName || 'Unknown',
          hours: hours,
          action: existingSchedule ? 'updated' : 'created',
          previousSchedule: previousSchedule,
          updatedSchedule: updatedSchedule.toObject(),
          assignmentId: updatedSchedule._id
        });
        assignmentIds.push(updatedSchedule._id);
      }
      
      // Create consolidated audit log for all projects assigned to this employee
      if (projectAudits.length > 0) {
        const projectNames = projectAudits.map(p => p.projectName).join(', ');
        const totalHours = projectAudits.reduce((sum, p) => sum + p.hours, 0);
        const hasUpdates = projectAudits.some(p => p.action === 'updated');
        const hasCreates = projectAudits.some(p => p.action === 'created');
        
        let actionDescription = '';
        let auditAction = '';
        if (hasUpdates && hasCreates) {
          actionDescription = 'created/updated';
          auditAction = 'bulk_assign';
        } else if (hasUpdates) {
          actionDescription = 'updated';
          auditAction = 'update';
        } else {
          actionDescription = 'created';
          auditAction = 'create';
        }
        
        const description = `${getUserRolePrefix(req)} ${actionDescription} assignment for ${empCode} on ${projectAudits.length} projects (${projectNames}) from ${startDate.toDateString()} to ${endDate.toDateString()} via ${getRouteContext(req)}`;
        
        const changes = {
          operation: 'manager_bulk_schedule_assignment_multiple_projects',
          employeeDetails: { empCode: empCode, name: employee.name },
          projectsCount: projectAudits.length,
          projectDetails: projectAudits.map(p => ({ projectName: p.projectName, hours: p.hours, action: p.action })),
          totalHours: totalHours,
          dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
          assignmentIds: assignmentIds
        };
        
        await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
      }
    } else {
      // Fallback case - redirect with error message
      return res.redirect(`/dashboard/manager/calaendar-view?error=${encodeURIComponent('Invalid assignment parameters. Please ensure you have selected employees and projects correctly.')}`);
    }
    res.redirect('/dashboard/manager/calendar-view');
  } catch (error) {
    console.error('Error assigning manager schedule:', error);
    res.status(500).send('Something went wrong');
  }
});

app.get('/dashboard/admin', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    // Basic counts
    const [totalEmployees, totalProjects, totalPractices, allSchedules, allProjects, allEmployees] = await Promise.all([
      Employee.countDocuments(),
      ProjectMaster.countDocuments(),
      PracticeMaster.countDocuments(),
      AssignedSchedule.find().populate('employee').populate('project').populate('practice'),
      ProjectMaster.find(),
      Employee.find({}, 'empCode name')
    ]);

    // Helper to parse different dailyHours key formats into Date objects
    function parseDateKeyToDate(key) {
      // ISO format yyyy-mm-dd
      if (/^\d{4}-\d{2}-\d{2}$/.test(key)) return new Date(key);
      // D-Mon-YYYY or DD-Month-YYYY (e.g., 1-Jul-2025 or 01-July-2025)
      const m = key.match(/^(\d{1,2})-([A-Za-z]{3,9})-(\d{4})$/);
      if (m) {
        const day = Number(m[1]);
        const monthName = m[2];
        const year = Number(m[3]);
        const month = new Date(Date.parse(monthName + ' 1, 2000')).getMonth();
        return new Date(year, month, day);
      }
      // Fallback: try Date.parse
      const parsed = Date.parse(key);
      if (!isNaN(parsed)) return new Date(parsed);
      return null;
    }

    // Hours assigned in the current month — use ?month=YYYY-MM when provided
    const monthParam = req.query.month; // expected format: 'YYYY-MM'
    let currentYear, currentMonth;
    if (monthParam && /^\d{4}-\d{2}$/.test(monthParam)) {
      const parts = monthParam.split('-');
      currentYear = parseInt(parts[0], 10);
      currentMonth = parseInt(parts[1], 10) - 1; // JS months are 0-indexed
    } else {
      const now = new Date();
      currentMonth = now.getMonth();
      currentYear = now.getFullYear();
    }
    let hoursAssignedThisMonth = 0;

    // Aggregations for top contributors and practice utilization
    const employeeHours = {}; // { empId: hours }
    const practiceHours = {}; // { practiceId: hours }
    const projectHours = {}; // { projectId: hours }

    allSchedules.forEach(s => {
      if (!s || !s.dailyHours) return;
      const empId = s.employee?._id ? s.employee._id.toString() : String(s.employee || 'unknown');
      const practiceId = s.practice?._id ? s.practice._id.toString() : (s.employee?.homePractice || 'unknown');
      const projId = s.project?._id ? s.project._id.toString() : String(s.project || 'unknown');

      Object.keys(s.dailyHours).forEach(k => {
        const parsed = parseDateKeyToDate(k);
        if (!parsed) return;
        if (parsed.getFullYear() === currentYear && parsed.getMonth() === currentMonth) {
          const h = Number(s.dailyHours[k]) || 0;
          hoursAssignedThisMonth += h;
          if (!employeeHours[empId]) employeeHours[empId] = 0;
          employeeHours[empId] += h;
          if (!practiceHours[practiceId]) practiceHours[practiceId] = 0;
          practiceHours[practiceId] += h;
          if (!projectHours[projId]) projectHours[projId] = 0;
          projectHours[projId] += h;
        }
      });
    });

    // Top contributors (employees)
    const topEmployees = Object.keys(employeeHours).map(empId => {
      const emp = allEmployees.find(e => String(e._id) === String(empId));
      return {
        id: empId,
        empCode: emp?.empCode || 'N/A',
        name: emp?.name || (employeeHours[empId] ? 'Employee' : 'Unknown'),
        hours: employeeHours[empId]
      };
    }).sort((a,b) => b.hours - a.hours).slice(0,5);

    // Top practices
    // Need practice names - find by id in PracticeMaster
    const practiceDocs = await PracticeMaster.find();
    const topPractices = Object.keys(practiceHours).map(pid => {
      const p = practiceDocs.find(x => String(x._id) === String(pid));
      return {
        id: pid,
        name: p?.practiceName || pid,
        hours: practiceHours[pid]
      };
    }).sort((a,b) => b.hours - a.hours).slice(0,5);

    // Projects: determine on-track vs delayed using endDate
    const today = new Date();
    let projectsOnTrack = 0, projectsDelayed = 0;
    allProjects.forEach(p => {
      if (p.endDate && new Date(p.endDate) < today) projectsDelayed++; else projectsOnTrack++;
    });


  // mini calendar removed: no weekly calendar computations

    // Available hours this month = employees * working days in month * 8
    function workingDaysInMonth(year, monthIndex) {
      const first = new Date(year, monthIndex, 1);
      const last = new Date(year, monthIndex + 1, 0);
      let count = 0;
      for (let d = new Date(first); d <= last; d.setDate(d.getDate() + 1)) {
        const wd = d.getDay();
        if (wd !== 0 && wd !== 6) count++;
      }
      return count;
    }
    const workdays = workingDaysInMonth(currentYear, currentMonth);
    const availableHours = totalEmployees * workdays * 8;

  // Utilization percent for the selected month (hours assigned / available hours)
  const utilizationPercent = availableHours > 0 ? Number(((hoursAssignedThisMonth / availableHours) * 100).toFixed(1)) : 0;

    // Quick actions links
    const quickActions = [
      { title: 'Allocate', url: '/schedule' },
      { title: 'Allocations', url: '/calendar-view' },
      { title: 'Reports', url: '/project-allocation-report' },
      { title: 'Users', url: '/view-users' }
    ];

    // --- Division utilization: sum of assigned hours grouped by project division (from ProjectMaster.dihClient) ---
    let divisionLabels = [];
    let divisionData = [];
    try {
      const projectsForDiv = await ProjectMaster.find().lean();
      const projDivisionMap = {};
      projectsForDiv.forEach(p => {
        const d = (p.dihClient && String(p.dihClient).trim()) || (p.cbslClient && String(p.cbslClient).trim()) || 'Unassigned';
        projDivisionMap[String(p._id)] = d;
      });

      const allSchedulesForDiv = await AssignedSchedule.find().lean();
      const divisionHoursMap = {};
      for (const s of allSchedulesForDiv) {
        const projId = s.project ? String(s.project) : null;
        const division = projId && projDivisionMap[projId] ? projDivisionMap[projId] : 'Unassigned';
        if (!divisionHoursMap[division]) divisionHoursMap[division] = 0;
        if (s.dailyHours) {
          // Only count hours that fall into the selected month/year
          Object.entries(s.dailyHours).forEach(([k, v]) => {
            try {
              const parsed = parseDateKeyToDate(k);
              if (!parsed) return;
              if (parsed.getFullYear() === currentYear && parsed.getMonth() === currentMonth) {
                divisionHoursMap[division] += Number(v) || 0;
              }
            } catch (e) { /* ignore malformed keys */ }
          });
        }
      }
      divisionLabels = Object.keys(divisionHoursMap);
      divisionData = divisionLabels.map(l => divisionHoursMap[l]);
    } catch (e) {
      console.warn('Failed to compute division utilization:', e);
    }

      // --- Practice-wise distribution: number of employees in each practice (from Employee.homePractice) ---
      let practiceLabels = [];
      let practiceData = [];
      try {
        const agg = await Employee.aggregate([
          { $group: { _id: { $ifNull: ['$homePractice', 'Unassigned'] }, count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ]);
        practiceLabels = agg.map(a => a._id);
        practiceData = agg.map(a => a.count);
      } catch (e) {
        console.warn('Failed to compute practice distribution:', e);
      }

      // --- Employee Utilization Buckets (Fully / Partially / Unutilized) ---
      // Assumption: per-employee available hours for the month = workdays * 8
      // Categorization: Fully = >=100%, Partially = 10% - 99%, Unutilized = <10%
      let employeeUtilCounts = [0, 0, 0]; // [fully, partial, unutilized]
      try {
        const perEmployeeAvailable = (workdays * 8) || 0;
        // Ensure we consider all employees (those with zero assigned hours count as unutilized)
        allEmployees.forEach(emp => {
          const empId = String(emp._id);
          const hrs = Number(employeeHours[empId] || 0);
          let pct = 0;
          if (perEmployeeAvailable > 0) pct = (hrs / perEmployeeAvailable) * 100;
          if (pct >= 100) {
            employeeUtilCounts[0] += 1; // fully
          } else if (pct >= 10) {
            employeeUtilCounts[1] += 1; // partial
          } else {
            employeeUtilCounts[2] += 1; // unutilized
          }
        });
      } catch (e) {
        console.warn('Failed to compute employee utilization buckets:', e);
        employeeUtilCounts = [0,0,0];
      }

    res.render('admin-welcome', {
      csrfToken: req.csrfToken(),
      title: 'Welcome Admin',
      layout: 'sidebar-layout',
      users: [], // keep for compatibility
      session: req.session,
      totalEmployees,
      totalProjects,
      totalPractices,
      hoursAssignedThisMonth,
      availableHours,
  utilizationPercent,
  topEmployees,
  topPractices,
  projectsOnTrack,
  projectsDelayed,
  divisionLabels,
  divisionData,
  practiceLabels,
  practiceData,
  employeeUtilCounts,
      quickActions
    });
  } catch (error) {
    console.error('Error fetching admin dashboard data:', error);
    // Fallback to simple render
    res.render('admin-welcome', {
      csrfToken: req.csrfToken(),
      title: 'Welcome Admin',
      layout: 'sidebar-layout',
      users: [],
      session: req.session
  , employeeUtilCounts: [0,0,0]
    });
  }
});

// ✅ Create User Route
app.post('/admin/create-user', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const { email, password, role } = req.body;

    // Validation
    if (!email || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    if (!['manager', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Create new user
    const newUser = new User({
      email,
      password: hashedPassword,
      role
    });

    await newUser.save();

    res.status(201).json({ 
      success: true, 
      message: 'User created successfully',
      user: {
        id: newUser._id,
        email: newUser.email,
        role: newUser.role
      }
    });

  } catch (error) {
    console.error('Error creating user:', error);
    
    // Handle duplicate key error
    if (error.code === 11000) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ✅ Reset User Password Route
app.post('/admin/reset-password', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const { userId, newPassword } = req.body;

    // Validation
    if (!userId || !newPassword) {
      return res.status(400).json({ error: 'User ID and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Hash new password
    const hashedPassword = bcrypt.hashSync(newPassword, 10);

    // Update password
    await User.findByIdAndUpdate(userId, { password: hashedPassword });

    res.status(200).json({ 
      success: true, 
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ✅ Delete User Route
app.post('/admin/delete-user', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const { userId } = req.body;

    // Validation
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    // Don't allow deleting yourself
    if (userId === req.session.user?.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    // Find and delete user
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({ 
      success: true, 
      message: 'User deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ✅ Updated View Employees Route
app.get('/dashboard/admin/view-employees', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const search = req.query.search || '';
    const limit = req.query.limit ? (req.query.limit === 'all' ? 'all' : parseInt(req.query.limit)) : 'all';


    const query = {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { empCode: { $regex: search, $options: 'i' } },
        { payrollCompany: { $regex: search, $options: 'i' } },
        { division: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } },
        { designation: { $regex: search, $options: 'i' } },
        { homePractice: { $regex: search, $options: 'i' } },
        { practiceManager: { $regex: search, $options: 'i' } }
      ]
    };

    const employeesQuery = Employee.find(query);
    if (limit !== 'all') {
      employeesQuery.limit(limit);
    }

    const employees = await employeesQuery;

    res.render('admin-dashboard', {
      employees,
      search,
      limit,
      csrfToken: req.csrfToken(),
      title: 'View Employees',
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error('Error fetching employees:', err);
    res.status(500).send('Error loading employee list.');
  }
});
// 🔍 API for dynamic search
app.get('/api/employees/search', isAuth, isAdmin, async (req, res) => {
  try {
    const search = req.query.q || '';

    const query = {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { empCode: { $regex: search, $options: 'i' } },
        { payrollCompany: { $regex: search, $options: 'i' } },
        { division: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } },
        { designation: { $regex: search, $options: 'i' } },
        { homePractice: { $regex: search, $options: 'i' } },
        { practiceManager: { $regex: search, $options: 'i' } }
      ]
    };

    const employees = await Employee.find(query).limit(50); // limit for performance
    res.json({ employees });
  } catch (err) {
    console.error('API search error:', err);
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});

// API routes for unified admin dashboard
app.get('/api/employees/all', isAuth, isAdmin, async (req, res) => {
  try {
    const employees = await Employee.find();
    res.json({ employees });
  } catch (err) {
    console.error('API employees/all error:', err);
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});

// API endpoint to get employees filtered by utilization status
app.get('/api/employees/by-utilization', isAuth, isAdmin, async (req, res) => {
  try {
    const { status, month } = req.query;
    
    // Parse month parameter (YYYY-MM format)
    let currentYear, currentMonth;
    if (month && /^\d{4}-\d{2}$/.test(month)) {
      const parts = month.split('-');
      currentYear = parseInt(parts[0], 10);
      currentMonth = parseInt(parts[1], 10) - 1; // JS months are 0-indexed
    } else {
      const now = new Date();
      currentMonth = now.getMonth();
      currentYear = now.getFullYear();
    }

    // Helper function to parse date keys from different formats
    function parseDateKeyToDate(key) {
      // ISO format yyyy-mm-dd
      if (/^\d{4}-\d{2}-\d{2}$/.test(key)) return new Date(key);
      // D-Mon-YYYY or DD-Month-YYYY (e.g., 1-Jul-2025 or 01-July-2025)
      const m = key.match(/^(\d{1,2})-([A-Za-z]{3,9})-(\d{4})$/);
      if (m) {
        const day = Number(m[1]);
        const monthName = m[2];
        const year = Number(m[3]);
        const month = new Date(Date.parse(monthName + ' 1, 2000')).getMonth();
        return new Date(year, month, day);
      }
      // Fallback: try Date.parse
      const parsed = Date.parse(key);
      if (!isNaN(parsed)) return new Date(parsed);
      return null;
    }

    // Calculate working days in the selected month
    function workingDaysInMonth(year, monthIndex) {
      const first = new Date(year, monthIndex, 1);
      const last = new Date(year, monthIndex + 1, 0);
      let count = 0;
      for (let d = new Date(first); d <= last; d.setDate(d.getDate() + 1)) {
        const wd = d.getDay();
        if (wd !== 0 && wd !== 6) count++;
      }
      return count;
    }

    const workdays = workingDaysInMonth(currentYear, currentMonth);
    const perEmployeeAvailable = (workdays * 8) || 0;

    // Get all employees and their schedules
    const [allEmployees, allSchedules] = await Promise.all([
      Employee.find({}, 'empCode name division designation homePractice practiceManager'),
      AssignedSchedule.find().populate('employee').populate('project')
    ]);

    // Calculate hours for each employee in the selected month
    const employeeHours = {};
    allSchedules.forEach(s => {
      if (!s || !s.dailyHours || !s.employee) return;
      const empId = s.employee._id.toString();
      
      Object.keys(s.dailyHours).forEach(k => {
        const parsed = parseDateKeyToDate(k);
        if (!parsed) return;
        if (parsed.getFullYear() === currentYear && parsed.getMonth() === currentMonth) {
          const h = Number(s.dailyHours[k]) || 0;
          if (!employeeHours[empId]) employeeHours[empId] = 0;
          employeeHours[empId] += h;
        }
      });
    });

    // Categorize employees and filter by requested status
    const filteredEmployees = [];
    allEmployees.forEach(emp => {
      const empId = emp._id.toString();
      const hrs = Number(employeeHours[empId] || 0);
      let pct = 0;
      if (perEmployeeAvailable > 0) pct = (hrs / perEmployeeAvailable) * 100;
      
      let utilizationStatus = '';
      if (pct >= 100) {
        utilizationStatus = 'fully';
      } else if (pct >= 10) {
        utilizationStatus = 'partially';
      } else {
        utilizationStatus = 'unutilized';
      }

      // Add employee to results if it matches the requested status
      if (status === utilizationStatus) {
        filteredEmployees.push({
          ...emp.toObject(),
          assignedHours: hrs,
          availableHours: perEmployeeAvailable,
          utilizationPercent: Math.round(pct * 100) / 100,
          utilizationStatus: utilizationStatus
        });
      }
    });

    // Sort by utilization percentage (descending)
    filteredEmployees.sort((a, b) => b.utilizationPercent - a.utilizationPercent);

    res.json({
      success: true,
      employees: filteredEmployees,
      status: status,
      month: `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}`,
      total: filteredEmployees.length
    });

  } catch (err) {
    console.error('Error fetching employees by utilization:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint to export employees by utilization status as CSV
app.get('/api/employees/export-csv', isAuth, isAdmin, async (req, res) => {
  try {
    const { status, month } = req.query;
    
    // Parse month parameter (YYYY-MM format)
    let currentYear, currentMonth;
    if (month && /^\d{4}-\d{2}$/.test(month)) {
      const parts = month.split('-');
      currentYear = parseInt(parts[0], 10);
      currentMonth = parseInt(parts[1], 10) - 1; // JS months are 0-indexed
    } else {
      const now = new Date();
      currentMonth = now.getMonth();
      currentYear = now.getFullYear();
    }

    // Helper function to parse date keys from different formats
    function parseDateKeyToDate(key) {
      // ISO format yyyy-mm-dd
      if (/^\d{4}-\d{2}-\d{2}$/.test(key)) return new Date(key);
      // D-Mon-YYYY or DD-Month-YYYY (e.g., 1-Jul-2025 or 01-July-2025)
      const m = key.match(/^(\d{1,2})-([A-Za-z]{3,9})-(\d{4})$/);
      if (m) {
        const day = Number(m[1]);
        const monthName = m[2];
        const year = Number(m[3]);
        const month = new Date(Date.parse(monthName + ' 1, 2000')).getMonth();
        return new Date(year, month, day);
      }
      // Fallback: try Date.parse
      const parsed = Date.parse(key);
      if (!isNaN(parsed)) return new Date(parsed);
      return null;
    }

    // Calculate working days in the selected month
    function workingDaysInMonth(year, monthIndex) {
      const first = new Date(year, monthIndex, 1);
      const last = new Date(year, monthIndex + 1, 0);
      let count = 0;
      for (let d = new Date(first); d <= last; d.setDate(d.getDate() + 1)) {
        const wd = d.getDay();
        if (wd !== 0 && wd !== 6) count++;
      }
      return count;
    }

    const workdays = workingDaysInMonth(currentYear, currentMonth);
    const perEmployeeAvailable = (workdays * 8) || 0;

    // Get all employees and their schedules
    const [allEmployees, allSchedules] = await Promise.all([
      Employee.find({}, 'empCode name division designation homePractice practiceManager'),
      AssignedSchedule.find().populate('employee').populate('project')
    ]);

    // Calculate hours for each employee in the selected month
    const employeeHours = {};
    allSchedules.forEach(s => {
      if (!s || !s.dailyHours || !s.employee) return;
      const empId = s.employee._id.toString();
      
      Object.keys(s.dailyHours).forEach(k => {
        const parsed = parseDateKeyToDate(k);
        if (!parsed) return;
        if (parsed.getFullYear() === currentYear && parsed.getMonth() === currentMonth) {
          const h = Number(s.dailyHours[k]) || 0;
          if (!employeeHours[empId]) employeeHours[empId] = 0;
          employeeHours[empId] += h;
        }
      });
    });

    // Categorize employees and filter by requested status
    const filteredEmployees = [];
    allEmployees.forEach(emp => {
      const empId = emp._id.toString();
      const hrs = Number(employeeHours[empId] || 0);
      let pct = 0;
      if (perEmployeeAvailable > 0) pct = (hrs / perEmployeeAvailable) * 100;
      
      let utilizationStatus = '';
      if (pct >= 100) {
        utilizationStatus = 'fully';
      } else if (pct >= 10) {
        utilizationStatus = 'partially';
      } else {
        utilizationStatus = 'unutilized';
      }

      // Add employee to results if it matches the requested status
      if (status === utilizationStatus) {
        filteredEmployees.push({
          'Employee Code': emp.empCode || '',
          'Name': emp.name || '',
          'Division': emp.division || '',
          'Practice': emp.homePractice || '',
          'Assigned Hours': `${hrs} hrs`,
          'Utilization %': `${Math.round(pct * 100) / 100}%`
        });
      }
    });

    // Sort by utilization percentage (descending)
    filteredEmployees.sort((a, b) => b['Utilization %'] - a['Utilization %']);

    if (filteredEmployees.length === 0) {
      return res.status(404).json({ error: 'No employees found for this utilization status' });
    }

    // Generate CSV content
    const headers = Object.keys(filteredEmployees[0]);
    const csvContent = [
      headers.join(','),
      ...filteredEmployees.map(employee => 
        headers.map(header => {
          const value = employee[header];
          // Escape quotes and wrap in quotes if contains comma, quote, or newline
          return typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))
            ? `"${value.replace(/"/g, '""')}"`
            : value;
        }).join(',')
      )
    ].join('\n');

    // Set response headers for CSV download
    const statusLabel = status.charAt(0).toUpperCase() + status.slice(1);
    const monthLabel = `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${statusLabel}_Utilized_Employees_${monthLabel}.csv"`);

    res.send(csvContent);

  } catch (err) {
    console.error('Error exporting employees CSV:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint to get employees by division
app.get('/api/employees/by-division', isAuth, isAdmin, async (req, res) => {
  try {
    const { division, month } = req.query;
    
    if (!division) {
      return res.status(400).json({ error: 'Division parameter is required' });
    }
    
    // Parse month parameter (YYYY-MM format)
    let currentYear, currentMonth;
    if (month && /^\d{4}-\d{2}$/.test(month)) {
      const parts = month.split('-');
      currentYear = parseInt(parts[0], 10);
      currentMonth = parseInt(parts[1], 10) - 1; // JS months are 0-indexed
    } else {
      const now = new Date();
      currentMonth = now.getMonth();
      currentYear = now.getFullYear();
    }

    // Helper function to parse date keys from different formats
    function parseDateKeyToDate(key) {
      // ISO format yyyy-mm-dd
      if (/^\d{4}-\d{2}-\d{2}$/.test(key)) return new Date(key);
      // D-Mon-YYYY or DD-Month-YYYY (e.g., 1-Jul-2025 or 01-July-2025)
      const m = key.match(/^(\d{1,2})-([A-Za-z]{3,9})-(\d{4})$/);
      if (m) {
        const day = Number(m[1]);
        const monthName = m[2];
        const year = Number(m[3]);
        const month = new Date(Date.parse(monthName + ' 1, 2000')).getMonth();
        return new Date(year, month, day);
      }
      // Fallback: try Date.parse
      const parsed = Date.parse(key);
      if (!isNaN(parsed)) return new Date(parsed);
      return null;
    }

    // Calculate working days in the selected month
    function workingDaysInMonth(year, monthIndex) {
      const first = new Date(year, monthIndex, 1);
      const last = new Date(year, monthIndex + 1, 0);
      let count = 0;
      for (let d = new Date(first); d <= last; d.setDate(d.getDate() + 1)) {
        const wd = d.getDay();
        if (wd !== 0 && wd !== 6) count++;
      }
      return count;
    }

    const workdays = workingDaysInMonth(currentYear, currentMonth);
    const perEmployeeAvailable = (workdays * 8) || 0;

    // Get projects for the selected division
    const projectsInDivision = await ProjectMaster.find({ dihClient: division });
    const projectIds = projectsInDivision.map(p => p._id.toString());

    // Get employees assigned to projects in this division
    const [allEmployees, schedulesInDivision] = await Promise.all([
      Employee.find({}, 'empCode name division designation homePractice practiceManager'),
      AssignedSchedule.find({ project: { $in: projectIds } }).populate('employee').populate('project')
    ]);

    // Calculate hours for each employee in the selected month
    const employeeHours = {};
    const employeesInDivision = new Set();
    
    schedulesInDivision.forEach(s => {
      if (!s || !s.dailyHours || !s.employee) return;
      const empId = s.employee._id.toString();
      employeesInDivision.add(empId);
      
      Object.keys(s.dailyHours).forEach(k => {
        const parsed = parseDateKeyToDate(k);
        if (!parsed) return;
        if (parsed.getFullYear() === currentYear && parsed.getMonth() === currentMonth) {
          const h = Number(s.dailyHours[k]) || 0;
          if (!employeeHours[empId]) employeeHours[empId] = 0;
          employeeHours[empId] += h;
        }
      });
    });

    // Filter employees that are assigned to projects in this division
    const filteredEmployees = [];
    allEmployees.forEach(emp => {
      const empId = emp._id.toString();
      if (employeesInDivision.has(empId)) {
        const hrs = Number(employeeHours[empId] || 0);
        let pct = 0;
        if (perEmployeeAvailable > 0) pct = (hrs / perEmployeeAvailable) * 100;
        
        let utilizationStatus = '';
        if (pct >= 100) {
          utilizationStatus = 'fully';
        } else if (pct >= 10) {
          utilizationStatus = 'partially';
        } else {
          utilizationStatus = 'unutilized';
        }

        filteredEmployees.push({
          ...emp.toObject(),
          assignedHours: hrs,
          availableHours: perEmployeeAvailable,
          utilizationPercent: Math.round(pct * 100) / 100,
          utilizationStatus: utilizationStatus
        });
      }
    });

    // Sort by utilization percentage (descending)
    filteredEmployees.sort((a, b) => b.utilizationPercent - a.utilizationPercent);

    res.json({
      success: true,
      employees: filteredEmployees,
      division: division,
      month: `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}`,
      total: filteredEmployees.length
    });

  } catch (err) {
    console.error('Error fetching employees by division:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint to get employees by practice
app.get('/api/employees/by-practice', isAuth, isAdmin, async (req, res) => {
  try {
    const { practice } = req.query;
    
    if (!practice) {
      return res.status(400).json({ error: 'Practice parameter is required' });
    }
    
    // Get employees in the selected practice
    const employeesInPractice = await Employee.find({ 
      homePractice: practice 
    }, 'empCode name division designation homePractice practiceManager');

    // Sort by employee code
    employeesInPractice.sort((a, b) => {
      const codeA = a.empCode || '';
      const codeB = b.empCode || '';
      return codeA.localeCompare(codeB);
    });

    res.json({
      success: true,
      employees: employeesInPractice,
      practice: practice,
      total: employeesInPractice.length
    });

  } catch (err) {
    console.error('Error fetching employees by practice:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint to export employees by practice as CSV
app.get('/api/employees/export-practice-csv', isAuth, isAdmin, async (req, res) => {
  try {
    const { practice } = req.query;
    
    if (!practice) {
      return res.status(400).json({ error: 'Practice parameter is required' });
    }
    
    // Get employees in the selected practice
    const employeesInPractice = await Employee.find({ 
      homePractice: practice 
    }, 'empCode name division designation homePractice practiceManager');

    // Sort by employee code
    employeesInPractice.sort((a, b) => {
      const codeA = a.empCode || '';
      const codeB = b.empCode || '';
      return codeA.localeCompare(codeB);
    });

    // Prepare CSV content
    const csvHeaders = [
      'Employee Code',
      'Name', 
      'Division',
      'Designation',
      'Home Practice',
      'Practice Manager'
    ];

    const csvRows = employeesInPractice.map(emp => [
      emp.empCode || '',
      emp.name || '',
      emp.division || '',
      emp.designation || '',
      emp.homePractice || '',
      emp.practiceManager || ''
    ]);

    // Create CSV content
    const csvContent = [
      csvHeaders.join(','),
      ...csvRows.map(row => row.map(field => {
        // Escape fields that contain commas, quotes, or newlines
        if (typeof field === 'string' && (field.includes(',') || field.includes('"') || field.includes('\n'))) {
          return `"${field.replace(/"/g, '""')}"`;
        }
        return field;
      }).join(','))
    ].join('\n');

    // Set response headers for file download
    const filename = `${practice}_employees.csv`;
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);

  } catch (err) {
    console.error('Error exporting practice employees CSV:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API endpoint to export employees by division as CSV
app.get('/api/employees/export-division-csv', isAuth, isAdmin, async (req, res) => {
  try {
    const { division, month } = req.query;
    
    if (!division) {
      return res.status(400).json({ error: 'Division parameter is required' });
    }
    
    // Parse month parameter (YYYY-MM format)
    let currentYear, currentMonth;
    if (month && /^\d{4}-\d{2}$/.test(month)) {
      const parts = month.split('-');
      currentYear = parseInt(parts[0], 10);
      currentMonth = parseInt(parts[1], 10) - 1; // JS months are 0-indexed
    } else {
      const now = new Date();
      currentMonth = now.getMonth();
      currentYear = now.getFullYear();
    }

    // Helper function to parse date keys from different formats
    function parseDateKeyToDate(key) {
      // ISO format yyyy-mm-dd
      if (/^\d{4}-\d{2}-\d{2}$/.test(key)) return new Date(key);
      // D-Mon-YYYY or DD-Month-YYYY (e.g., 1-Jul-2025 or 01-July-2025)
      const m = key.match(/^(\d{1,2})-([A-Za-z]{3,9})-(\d{4})$/);
      if (m) {
        const day = Number(m[1]);
        const monthName = m[2];
        const year = Number(m[3]);
        const month = new Date(Date.parse(monthName + ' 1, 2000')).getMonth();
        return new Date(year, month, day);
      }
      // Fallback: try Date.parse
      const parsed = Date.parse(key);
      if (!isNaN(parsed)) return new Date(parsed);
      return null;
    }

    // Calculate working days in the selected month
    function workingDaysInMonth(year, monthIndex) {
      const first = new Date(year, monthIndex, 1);
      const last = new Date(year, monthIndex + 1, 0);
      let count = 0;
      for (let d = new Date(first); d <= last; d.setDate(d.getDate() + 1)) {
        const wd = d.getDay();
        if (wd !== 0 && wd !== 6) count++;
      }
      return count;
    }

    const workdays = workingDaysInMonth(currentYear, currentMonth);
    const perEmployeeAvailable = (workdays * 8) || 0;

    // Get projects for the selected division
    const projectsInDivision = await ProjectMaster.find({ dihClient: division });
    const projectIds = projectsInDivision.map(p => p._id.toString());

    // Get employees assigned to projects in this division
    const [allEmployees, schedulesInDivision] = await Promise.all([
      Employee.find({}, 'empCode name division designation homePractice practiceManager'),
      AssignedSchedule.find({ project: { $in: projectIds } }).populate('employee').populate('project')
    ]);

    // Calculate hours for each employee in the selected month
    const employeeHours = {};
    const employeesInDivision = new Set();
    
    schedulesInDivision.forEach(s => {
      if (!s || !s.dailyHours || !s.employee) return;
      const empId = s.employee._id.toString();
      employeesInDivision.add(empId);
      
      Object.keys(s.dailyHours).forEach(k => {
        const parsed = parseDateKeyToDate(k);
        if (!parsed) return;
        if (parsed.getFullYear() === currentYear && parsed.getMonth() === currentMonth) {
          const h = Number(s.dailyHours[k]) || 0;
          if (!employeeHours[empId]) employeeHours[empId] = 0;
          employeeHours[empId] += h;
        }
      });
    });

    // Filter employees that are assigned to projects in this division
    const filteredEmployees = [];
    allEmployees.forEach(emp => {
      const empId = emp._id.toString();
      if (employeesInDivision.has(empId)) {
        const hrs = Number(employeeHours[empId] || 0);
        let pct = 0;
        if (perEmployeeAvailable > 0) pct = (hrs / perEmployeeAvailable) * 100;

        filteredEmployees.push({
          'Employee Code': emp.empCode || '',
          'Name': emp.name || '',
          'Division': emp.division || '',
          'Practice': emp.homePractice || '',
          'Assigned Hours': `${hrs} hrs`,
          'Utilization %': `${Math.round(pct * 100) / 100}%`
        });
      }
    });

    // Sort by utilization percentage (descending)
    filteredEmployees.sort((a, b) => {
      const aPercent = parseFloat(a['Utilization %'].replace('%', ''));
      const bPercent = parseFloat(b['Utilization %'].replace('%', ''));
      return bPercent - aPercent;
    });

    if (filteredEmployees.length === 0) {
      return res.status(404).json({ error: 'No employees found for this division' });
    }

    // Generate CSV content
    const headers = Object.keys(filteredEmployees[0]);
    const csvContent = [
      headers.join(','),
      ...filteredEmployees.map(employee => 
        headers.map(header => {
          const value = employee[header];
          // Escape quotes and wrap in quotes if contains comma, quote, or newline
          return typeof value === 'string' && (value.includes(',') || value.includes('"') || value.includes('\n'))
            ? `"${value.replace(/"/g, '""')}"`
            : value;
        }).join(',')
      )
    ].join('\n');

    // Set response headers for CSV download
    const monthLabel = `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}`;
    const safeFileName = division.replace(/[^a-z0-9]/gi, '_');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${safeFileName}_Division_Employees_${monthLabel}.csv"`);

    res.send(csvContent);

  } catch (err) {
    console.error('Error exporting division employees CSV:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/projects/all', isAuth, isAdmin, async (req, res) => {
  try {
    const projects = await ProjectMaster.find();
    res.json({ projects });
  } catch (err) {
    console.error('API projects/all error:', err);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

app.get('/api/practices/all', isAuth, isAdmin, async (req, res) => {
  try {
    const practices = await PracticeMaster.find();
    res.json({ practices });
  } catch (err) {
    console.error('API practices/all error:', err);
    res.status(500).json({ error: 'Failed to fetch practices' });
  }
});

// Bulk delete routes
app.post('/project-master/bulk-delete', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    // Handle multiple possible field names for flexibility
    const ids = req.body['ids[]'] || req.body.ids || req.body.projectIds;
    
    if (!ids) {
      return res.status(400).json({ success: false, message: 'No project IDs provided' });
    }
    
    // Ensure ids is always an array
    const idsArray = Array.isArray(ids) ? ids : [ids];
    
    if (idsArray.length === 0) {
      return res.status(400).json({ success: false, message: 'No project IDs provided' });
    }
    
  // Delete the projects
  const result = await ProjectMaster.deleteMany({ _id: { $in: idsArray } });
  res.json({ success: true, message: `${result.deletedCount} projects deleted successfully` });
  } catch (err) {
    console.error('Error bulk deleting projects:', err);
    res.status(500).json({ success: false, message: 'Failed to delete projects' });
  }
});

app.post('/practice-master/bulk-delete', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    // Handle multiple possible field names for flexibility
    const ids = req.body['ids[]'] || req.body.ids || req.body.practiceIds;
    if (!ids) {
      // If called via AJAX/fetch, return JSON
      if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
        return res.status(400).json({ success: false, message: 'No practice IDs provided' });
      } else {
        return res.status(400).send('No practices selected for deletion.');
      }
    }
    // Ensure ids is always an array
    const idsArray = Array.isArray(ids) ? ids : [ids];
    if (idsArray.length === 0) {
      if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
        return res.status(400).json({ success: false, message: 'No practice IDs provided' });
      } else {
        return res.status(400).send('No practices selected for deletion.');
      }
    }
    // Delete the practices
    const result = await PracticeMaster.deleteMany({ _id: { $in: idsArray } });
    // If called via AJAX/fetch, return JSON
    if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
      return res.json({ success: true, message: `${result.deletedCount} practices deleted successfully` });
    } else {
      // If called via form, redirect
      return res.redirect('/view-practice-master');
    }
  } catch (err) {
    console.error('Error bulk deleting practices:', err);
    if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
      res.status(500).json({ success: false, message: 'Failed to delete practices' });
    } else {
      res.status(500).send('Error deleting practices.');
    }
  }
});

// View Project Master
app.get('/view-project-master', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const projects = await ProjectMaster.find().lean();

    // Format startDate & endDate to only 'YYYY-MM-DD'
    projects.forEach(p => {
      p.startDate = p.startDate?.toISOString().split('T')[0];
      p.endDate = p.endDate?.toISOString().split('T')[0];
    });

  // Get distinct CBSL clients and divisions from existing ProjectMaster records
  const cbslClients = (await ProjectMaster.distinct('cbslClient')).filter(Boolean).sort();
  const divisions = (await ProjectMaster.distinct('dihClient')).filter(Boolean).sort();

    res.render('view-project-master', {
      title: 'Project Master',
      projects,
  cbslClients,
  divisions,
      csrfToken: req.csrfToken(),
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error('Error loading project master:', err);
    res.status(500).send('Error loading project master records.');
  }
});

app.post('/project-master/add', isAuth, isAdmin, async (req, res) => {
  try {
    let {
      projectName,
      startDate,
      endDate,
      projectManager,
      cbslClient,
      dihClient
    } = req.body;

    // Only take date part
    const formattedStartDate = startDate.split('T')[0];
    const formattedEndDate = endDate.split('T')[0];

    // Normalize client/division to existing DB casing if a case-insensitive match exists
    const escapeRegExp = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (cbslClient) {
      const existing = await ProjectMaster.findOne({ cbslClient: { $regex: '^' + escapeRegExp(cbslClient) + '$', $options: 'i' } });
      if (existing && existing.cbslClient) cbslClient = existing.cbslClient;
    }
    if (dihClient) {
      const existingD = await ProjectMaster.findOne({ dihClient: { $regex: '^' + escapeRegExp(dihClient) + '$', $options: 'i' } });
      if (existingD && existingD.dihClient) dihClient = existingD.dihClient;
    }

    const newProject = await ProjectMaster.create({
      projectName,
      startDate: formattedStartDate,
      endDate: formattedEndDate,
      projectManager,
      cbslClient,
      dihClient
    });

    // Admin audit logging for project creation
    const description = `Admin ${req.session.user?.email} created project: ${projectName} via admin-project-master-add`;
    const changes = {
      operation: 'admin_create_project',
      projectDetails: {
        projectName,
        startDate: formattedStartDate,
        endDate: formattedEndDate,
        projectManager,
        cbslClient,
        dihClient
      }
    };
    await logAuditAction(req, 'create', null, null, newProject.toObject(), description, changes);

    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error adding project:', err);
    res.status(500).send('Error adding project.');
  }
});

app.post('/project-master/edit', isAuth, isAdmin, async (req, res) => {
  try {
    let {
      _id,
      projectName,
      startDate,
      endDate,
      projectManager,
      cbslClient,
      dihClient
    } = req.body;

    const formattedStartDate = startDate.split('T')[0];
    const formattedEndDate = endDate.split('T')[0];

    // Normalize client/division to existing DB casing if a case-insensitive match exists
    const escapeRegExp = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (cbslClient) {
      const existing = await ProjectMaster.findOne({ cbslClient: { $regex: '^' + escapeRegExp(cbslClient) + '$', $options: 'i' } });
      if (existing && existing.cbslClient) cbslClient = existing.cbslClient;
    }
    if (dihClient) {
      const existingD = await ProjectMaster.findOne({ dihClient: { $regex: '^' + escapeRegExp(dihClient) + '$', $options: 'i' } });
      if (existingD && existingD.dihClient) dihClient = existingD.dihClient;
    }

    // Get original project data for audit logging
    const originalProject = await ProjectMaster.findById(_id);

    const updatedProject = await ProjectMaster.findByIdAndUpdate(_id, {
      projectName,
      startDate: formattedStartDate,
      endDate: formattedEndDate,
      projectManager,
      cbslClient,
      dihClient
    }, { new: true });

    // Admin audit logging for project update
    if (originalProject && updatedProject) {
      const description = `Admin ${req.session.user?.email} updated project: ${projectName} via admin-project-master-edit`;
      const changes = {
        operation: 'admin_update_project',
        projectDetails: {
          projectName,
          originalData: originalProject.toObject(),
          updatedData: updatedProject.toObject()
        }
      };
      await logAuditAction(req, 'update', null, originalProject.toObject(), updatedProject.toObject(), description, changes);
    }

    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error editing project:', err);
    res.status(500).send('Error editing project.');
  }
});


app.post('/project-master/delete/:id', isAuth, isAdmin, async (req, res) => {
  try {
    // Get original project data for audit logging
    const originalProject = await ProjectMaster.findById(req.params.id);
    
    await ProjectMaster.findByIdAndDelete(req.params.id);
    
    // Admin audit logging for project deletion
    if (originalProject) {
      const description = `Admin ${req.session.user?.email} deleted project: ${originalProject.projectName} via admin-project-master-delete`;
      const changes = {
        operation: 'admin_delete_project',
        projectDetails: {
          projectName: originalProject.projectName,
          deletedData: originalProject.toObject()
        }
      };
      await logAuditAction(req, 'delete', null, originalProject.toObject(), null, description, changes);
    }
    
    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error deleting project:', err);
    res.status(500).send('Error deleting project.');
  }
});




// Upload Employees Form
app.get('/upload-employees', isAuth, isAdmin, csrfProtection, (req, res) => {
  res.render('upload-employees', { csrfToken: req.csrfToken() });
});

// Upload Employees POST
app.post('/upload-employees',
  isAuth,
  isAdmin,
  upload.single('excelfile'),
  csrfProtection,
  async (req, res) => {
    const filePath = req.file.path;
    try {
      const workbook = xlsx.readFile(filePath);
      const sheetName = workbook.SheetNames[0];
      const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

      for (const emp of data) {
        if (emp['Emp. Code'] && emp['Resource Name']) {
          await Employee.findOneAndUpdate(
            { empCode: emp['Emp. Code'] },
            {
              empCode: emp['Emp. Code'],
              name: emp['Resource Name'],
              payrollCompany: emp['Payroll Company'],
              division: emp['Division'],
              location: emp['Location'],
              designation: emp['Designation'],
              homePractice: emp['Home Practice'],
              practiceManager: emp['Practice Manager'],
              project: ''
            },
            { upsert: true, new: true }
          );
        }
      }

      fs.unlinkSync(filePath);
      res.redirect('/dashboard/admin/view-employees');
    } catch (err) {
      console.error('Excel Parse Error:', err);
      res.status(500).send('Error processing file.');
    }
  }
);

// Upload Project Master GET
app.get('/upload-project-master', isAuth, isAdmin, csrfProtection, (req, res) => {
  res.render('upload-project-master', { csrfToken: req.csrfToken() });
});

// Upload Project Master POST
const parseDate = (value) => {
  const date = new Date(value);
  return isNaN(date.getTime()) ? null : date;
};





app.post('/upload-project-master', isAuth, isAdmin, upload.single('projectFile'), csrfProtection, async (req, res) => {
  const filePath = req.file.path;

  try {
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    for (const row of data) {
      if (row['Project Name']) {
        const startDate = parseDate(row['Start Date']);
        const endDate = parseDate(row['End Date']);

        // Upsert by projectName to avoid duplicate ProjectMaster documents
        await ProjectMaster.findOneAndUpdate(
          { projectName: row['Project Name'] },
          {
            projectName: row['Project Name'],
            startDate,
            endDate,
            projectManager: row['Project Manager'],
            cbslClient: row['CBSL Client'],
            dihClient: row['Division']
          },
          { upsert: true, new: true, setDefaultsOnInsert: true }
        );
      }
    }

    fs.unlinkSync(filePath);
    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error uploading project master:', err);
    res.status(500).send('Upload failed.');
  }
});

// --- Practice Master CRUD ---
// Add Practice
app.post('/practice-master/add', isAuth, isAdmin, async (req, res) => {
  try {
    const { practiceName, practiceManager } = req.body;
    await PracticeMaster.create({ practiceName, practiceManager });
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error adding practice:', err);
    res.status(500).send('Error adding practice.');
  }
});

// Edit Practice
app.post('/practice-master/edit', isAuth, isAdmin, async (req, res) => {
  try {
    const { _id, practiceName, practiceManager } = req.body;
    await PracticeMaster.findByIdAndUpdate(_id, { practiceName, practiceManager });
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error editing practice:', err);
    res.status(500).send('Error editing practice.');
  }
});

// Delete Practice
app.post('/practice-master/delete/:id', isAuth, isAdmin, async (req, res) => {
  try {
    await PracticeMaster.findByIdAndDelete(req.params.id);
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error deleting practice:', err);
    res.status(500).send('Error deleting practice.');
  }
});

// Upload Practice Master GET
app.get('/upload-practice-master', isAuth, isAdmin, csrfProtection, (req, res) => {
  res.render('upload-practice-master', { csrfToken: req.csrfToken() });
});

// Upload Practice Master POST
app.post('/upload-practice-master', isAuth, isAdmin, upload.single('practiceFile'), csrfProtection, async (req, res) => {
  const filePath = req.file.path;
  try {
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    for (const row of data) {
      if (row['SW Practice']) {
        await PracticeMaster.create({
          practiceName: row['SW Practice'],
          practiceManager: row['Practice Manager']
        });
      }
    }

    fs.unlinkSync(filePath);
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error uploading practice master:', err);
    res.status(500).send('Upload failed.');
  }
});
// View Project Master
// app.get('/view-project-master', isAuth, isAdmin, async (req, res) => {
//   try {
//     const projects = await ProjectMaster.find();
//     res.render('view-project-master', { projects });
//   } catch (err) {
//     console.error("Error fetching project master:", err);
//     res.status(500).send('Error loading project master.');
//   }
// });

// View Practice Master
app.get('/view-practice-master', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const practices = await PracticeMaster.find();
    res.render('view-practice-master', { 
      practices,
      csrfToken: req.csrfToken(),
      title: 'Practice Master',
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error("Error fetching practice master:", err);
    res.status(500).send('Error loading practice master.');
  }
});

// Assigned Resources Page


app.get('/assigned-resources', isAuth, isAdmin, async (req, res) => {
  try {
    // Get filter params
    const employeeFilter = req.query.employee || '';
    const projectFilter = req.query.project || '';
    const fromMonthFilter = req.query.fromMonth || '';
    const toMonthFilter = req.query.toMonth || '';

    // Build query for AssignedSchedule
    let scheduleQuery = {};
    if (employeeFilter) {
      const empDoc = await Employee.findOne({ empCode: employeeFilter });
      if (empDoc) scheduleQuery.employee = empDoc._id;
    }
    if (projectFilter) {
      const projDoc = await ProjectMaster.findOne({ projectName: projectFilter });
      if (projDoc) scheduleQuery.project = projDoc._id;
    }

    // Only show one schedule per employee/project (latest)
    const allSchedules = await AssignedSchedule.find(scheduleQuery)
      .populate('employee')
      .populate('project')
      .populate('practice');
    // Deduplicate by employee+project using stringified ObjectIds
    const latestSchedules = {};
    for (const s of allSchedules) {
      const empId = s.employee?._id ? s.employee._id.toString() : String(s.employee);
      const projId = s.project?._id ? s.project._id.toString() : String(s.project);
      const key = `${empId}-${projId}`;
      // Always keep the latest schedule (by _id timestamp)
      if (!latestSchedules[key] || (s._id > latestSchedules[key]._id)) {
        latestSchedules[key] = s;
      }
    }
    const uniqueSchedules = Object.values(latestSchedules);

    // Generate dateRange for the selected month range (or current month if not selected)
    let startYear, startMonth, endYear, endMonth;
    if (fromMonthFilter && toMonthFilter) {
      // fromMonthFilter and toMonthFilter format: 'YYYY-MM'
      const fromParts = fromMonthFilter.split('-');
      const toParts = toMonthFilter.split('-');
      startYear = parseInt(fromParts[0], 10);
      startMonth = parseInt(fromParts[1], 10) - 1; // JS months are 0-indexed
      endYear = parseInt(toParts[0], 10);
      endMonth = parseInt(toParts[1], 10) - 1;
    } else {
      const now = new Date();
      startYear = now.getFullYear();
      startMonth = now.getMonth();
      endYear = startYear;
      endMonth = startMonth;
    }
    // Generate all dates between start and end month (inclusive)
    const dateRange = [];
    let currentYear = startYear;
    let currentMonth = startMonth;
    while (currentYear < endYear || (currentYear === endYear && currentMonth <= endMonth)) {
      const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
      for (let d = 1; d <= daysInMonth; d++) {
        const dateObj = new Date(currentYear, currentMonth, d);
        const day = dateObj.getDate();
        const monthName = dateObj.toLocaleString('default', { month: 'short' });
        const year = dateObj.getFullYear();
        dateRange.push(`${day}-${monthName}-${year}`);
      }
      currentMonth++;
      if (currentMonth > 11) {
        currentMonth = 0;
        currentYear++;
      }
    }

    // Generate all dates for current year (YYYY-MM-DD)
    const allYearDates = [];
    let minDate = new Date(startYear + '-01-01');
    let maxDate = new Date(endYear + '-12-31');
    for (let d = new Date(minDate); d <= maxDate; d.setDate(d.getDate() + 1)) {
      let dateStr = d.toISOString().slice(0,10);
      allYearDates.push(dateStr);
    }

    // Get all employees and projects for filter dropdowns
    const allEmployees = await Employee.find({}, 'empCode name division designation');
    const allProjects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient');

    res.render('assigned-resources', {
      schedules: uniqueSchedules,
      dateRange,
      allYearDates,
      allEmployees,
      allProjects,
      employeeFilter,
      projectFilter,
      fromMonthFilter,
      toMonthFilter,
      errorMessage: req.query.error || '',
      layout: 'sidebar-layout',
      title: 'Assigned Resources'
    });
  } catch (err) {
    console.error('Error loading assigned resources page:', err);
    res.status(500).send('Internal Server Error');
  }
});

// CREATE: Add a new schedule (Admin only)
app.post('/assigned-resources', isAuth, isAdmin, async (req, res) => {
  try {
    // console.log('POST /assigned-resources', req.body);
    const { empCode, dailyHours, projectAssigned } = req.body;
    // Find employee and project references
    const employeeDoc = await Employee.findOne({ empCode });
    const projectDoc = await ProjectMaster.findOne({ projectName: projectAssigned });
    if (!employeeDoc || !projectDoc) {
      return res.status(400).json({ success: false, error: 'Employee or Project not found' });
    }
    // Parse dailyHours if sent as JSON string or object
    let dailyHoursObj = {};
    if (typeof dailyHours === 'string') {
      try { dailyHoursObj = JSON.parse(dailyHours); } catch { dailyHoursObj = {}; }
    } else if (typeof dailyHours === 'object') {
      dailyHoursObj = dailyHours;
    }
    // Convert all values to numbers and format keys to 'D-MMM'
    function formatDateKey(dateStr) {
      // Accepts 'YYYY-MM-DD' or 'D-MMM'
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        const year = d.getFullYear();
        return `${day}-${monthName}-${year}`;
      }
      return dateStr;
    }
    let formattedDailyHours = {};
    Object.keys(dailyHoursObj).forEach(date => {
      formattedDailyHours[formatDateKey(date)] = Number(dailyHoursObj[date]) || 0;
    });
    // Check for existing schedule for this employee and project
    let existingSchedule = await AssignedSchedule.findOne({ employee: employeeDoc._id, project: projectDoc._id });
    if (existingSchedule) {
      // Update dailyHours if already exists
      existingSchedule.dailyHours = formattedDailyHours;
      await existingSchedule.save();
      res.status(200).json({ success: true, schedule: existingSchedule, updated: true });
    } else {
      const newSchedule = new AssignedSchedule({
        employee: employeeDoc._id,
        project: projectDoc._id,
        dailyHours: formattedDailyHours
      });
      await newSchedule.save();
      res.status(201).json({ success: true, schedule: newSchedule, created: true });
    }
  } catch (err) {
    console.error('Error in POST /assigned-resources:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// READ: Get a schedule by ID (for Edit) (Admin only)
app.get('/assigned-resources/:id', isAuth, async (req, res) => {
  try {
    // console.log('GET /assigned-resources/:id', req.params.id);
    if (!req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      console.error('Invalid ObjectId format:', req.params.id);
      return res.status(400).json({ success: false, error: 'Invalid schedule ID format' });
    }
    const schedule = await AssignedSchedule.findById(req.params.id);
    if (!schedule) {
      console.error('Schedule not found for ID:', req.params.id);
      return res.status(404).json({ success: false, error: 'Schedule not found' });
    }
    res.json({ success: true, schedule });
  } catch (err) {
    console.error('Error in GET /assigned-resources/:id:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// UPDATE: Edit a schedule (Admin only)
app.put('/assigned-resources/:id', isAuth, async (req, res) => {
  try {
    //console.log('PUT /assigned-resources/:id', req.params.id);
    //console.log('Request body:', req.body);
    // Support both flat and nested project/dailyHours from AJAX
    const updateFields = {};
    // Parse flat fields into nested objects if needed
    // Project
    let projectName = req.body['project[projectName]'] || (req.body.project && req.body.project.projectName);
    if (projectName) {
      // Find ProjectMaster by name and use its ObjectId
      const projectDoc = await ProjectMaster.findOne({ projectName: projectName });
      if (projectDoc) {
        updateFields['project'] = projectDoc._id;
      } else {
        // If not found, do not update project and log warning
        console.warn('Project not found for name:', projectName);
      }
    }
    // Daily hours
    let dailyHoursObj = {};
    Object.keys(req.body).forEach(key => {
      const dhMatch = key.match(/^dailyHours\[(.+)\]$/);
      if (dhMatch) {
        // Accept both D-MMM and YYYY-MM-DD keys, always convert to D-MMM
        let rawKey = dhMatch[1];
        let formattedKey = formatDateKey(rawKey);
        dailyHoursObj[formattedKey] = Number(req.body[key]) || 0;
      }
    });
    // Format keys to 'D-MMM' for consistency with dateRange
    function formatDateKey(dateStr) {
      // Accepts 'YYYY-MM-DD', 'D-MMM', or other formats
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        const year = d.getFullYear();
        return `${day}-${monthName}-${year}`;
      }
      // If already D-MMM, return as is
      if (/^\d{1,2}-[A-Za-z]{3}$/.test(dateStr)) {
        return dateStr;
      }
      // Try to parse other date formats
      const d = new Date(dateStr);
      if (!isNaN(d.getTime())) {
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        const year = d.getFullYear();
        return `${day}-${monthName}-${year}`;
      }
      return dateStr;
    }
    // Over-allocation validation: for each day, sum all hours for this employee across all projects
    if (Object.keys(dailyHoursObj).length > 0) {
      // Find the schedule being updated
      const currentSchedule = await AssignedSchedule.findById(req.params.id);
      if (currentSchedule && currentSchedule.employee) {
        for (const dateKey of Object.keys(dailyHoursObj)) {
          // Sum all hours for this employee on this day across all projects except this one
          const otherSchedules = await AssignedSchedule.find({ employee: currentSchedule.employee, _id: { $ne: req.params.id } });
          let totalOther = 0;
          for (const sched of otherSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[dateKey];
            totalOther += Number(dh) || 0;
          }
          let newTotal = totalOther + Number(dailyHoursObj[dateKey]) || 0;
          if (newTotal > 8) {
            return res.status(400).json({ success: false, error: `Over allocation: Total hours for employee exceed 8 on ${dateKey} (${newTotal} hours)` });
          }
        }
      }
      updateFields['dailyHours'] = dailyHoursObj;
    }

    //console.log('Update fields:', updateFields);
    
    // Get original schedule for audit logging
    const originalSchedule = await AssignedSchedule.findById(req.params.id).populate('employee').populate('project');
    
    const updated = await AssignedSchedule.findByIdAndUpdate(
      req.params.id,
      { $set: updateFields },
      { new: true }
    );
    if (updated) {
      // Fetch with project populated for frontend display
      const populated = await AssignedSchedule.findById(updated._id)
        .populate('employee')
        .populate('project')
        .populate('practice');
      
      // Admin audit logging for assigned resources update
      if (req.session.user?.role === 'admin') {
        const description = `Admin ${req.session.user?.email} updated assignment for ${originalSchedule?.employee?.empCode} (${originalSchedule?.employee?.name}) on project ${originalSchedule?.project?.projectName} via admin-assigned-resources-edit`;
        const changes = {
          operation: 'admin_update_assignment',
          employeeDetails: { empCode: originalSchedule?.employee?.empCode, name: originalSchedule?.employee?.name },
          projectDetails: { projectName: originalSchedule?.project?.projectName },
          updatedFields: updateFields,
          dailyHours: dailyHoursObj
        };
        await logAuditAction(req, 'update', req.params.id, originalSchedule?.toObject(), populated.toObject(), description, changes);
      }
      
      //console.log('Update success:', populated);
      res.json({ success: true, schedule: populated });
    } else {
      console.warn('Schedule not found for update:', req.params.id);
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Error in PUT /assigned-resources/:id:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE: Remove a schedule (Admin only)
app.delete('/assigned-resources/:id', isAuth, isAdmin, async (req, res) => {
  try {
    //console.log('DELETE /assigned-resources/:id', req.params.id);
    
    // Get original schedule for audit logging before deletion
    const originalSchedule = await AssignedSchedule.findById(req.params.id).populate('employee').populate('project');
    
    let result = await AssignedSchedule.deleteOne({ _id: req.params.id });
    if (result.deletedCount === 0) {
      result = await AssignedSchedule.deleteOne({ _id: req.params.id.toString() });
    }
    if (result.deletedCount > 0) {
      // Admin audit logging for assigned resources deletion
      if (originalSchedule) {
        const description = `Admin ${req.session.user?.email} deleted assignment for ${originalSchedule?.employee?.empCode} (${originalSchedule?.employee?.name}) on project ${originalSchedule?.project?.projectName} via admin-assigned-resources-delete`;
        const changes = {
          operation: 'admin_delete_assignment',
          employeeDetails: { empCode: originalSchedule?.employee?.empCode, name: originalSchedule?.employee?.name },
          projectDetails: { projectName: originalSchedule?.project?.projectName },
          deletedSchedule: originalSchedule.toObject()
        };
        await logAuditAction(req, 'delete', req.params.id, originalSchedule.toObject(), null, description, changes);
      }
      
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Error in DELETE /assigned-resources/:id:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// BULK DELETE: Remove multiple schedules (Admin only)
app.post('/assigned-resources/bulk-delete', isAuth, isAdmin, async (req, res) => {
  try {
    console.log('📍 Bulk delete request received:', req.body);
    
    const ids = req.body['ids[]'] || req.body.ids || req.body.scheduleIds;
    
    if (!ids) {
      console.log('❌ No IDs provided in request');
      return res.status(400).json({ success: false, error: 'No schedule IDs provided' });
    }
    
    // Ensure ids is always an array
    const idsArray = Array.isArray(ids) ? ids : [ids];
    
    if (idsArray.length === 0) {
      console.log('❌ Empty IDs array');
      return res.status(400).json({ success: false, error: 'No schedule IDs provided' });
    }
    
    console.log('🎯 Processing bulk delete for IDs:', idsArray);
    
    // Get original schedules for audit logging before deletion
    const originalSchedules = await AssignedSchedule.find({ _id: { $in: idsArray } }).populate('employee').populate('project');
    
    // Delete the schedules
    const result = await AssignedSchedule.deleteMany({ _id: { $in: idsArray } });
    
    if (result.deletedCount > 0) {
      // Create consolidated audit log for bulk deletion
      const deletedSchedulesInfo = originalSchedules.map(s => ({
        empCode: s.employee?.empCode || 'N/A',
        empName: s.employee?.name || 'N/A',
        projectName: s.project?.projectName || 'N/A',
        assignmentId: s._id
      }));
      
      const employeeNames = deletedSchedulesInfo.map(s => `${s.empCode} (${s.empName})`).join(', ');
      const projectNames = [...new Set(deletedSchedulesInfo.map(s => s.projectName))].join(', ');
      
      const description = `Admin ${req.session.user?.email} bulk deleted ${result.deletedCount} assignments for employees: ${employeeNames} from projects: ${projectNames} via admin-assigned-resources-bulk-delete`;
      
      const changes = {
        operation: 'admin_bulk_delete_assignments',
        deletedCount: result.deletedCount,
        deletedSchedules: deletedSchedulesInfo,
        employeeCount: [...new Set(deletedSchedulesInfo.map(s => s.empCode))].length,
        projectCount: [...new Set(deletedSchedulesInfo.map(s => s.projectName))].length
      };
      
      // For bulk operations, use the first employee and project info for the main fields
      const firstEmployee = originalSchedules[0]?.employee;
      const firstProject = originalSchedules[0]?.project;
      
      // Create a custom audit log entry that populates the Employee and Project columns properly
      const auditEntry = await AuditLog.create({
        manager: req.session.user?.email || 'Unknown',
        managerName: req.session.user?.email?.split('@')[0] || 'Unknown',
        userRole: req.session.user?.role || 'admin',
        action: 'delete',
        assignmentId: originalSchedules[0]?._id,
        employeeCode: result.deletedCount === 1 ? firstEmployee?.empCode : `${result.deletedCount} employees`,
        employeeName: result.deletedCount === 1 ? firstEmployee?.name : employeeNames,
        projectName: [...new Set(deletedSchedulesInfo.map(s => s.projectName))].length === 1 ? 
                    deletedSchedulesInfo[0].projectName : 
                    `${[...new Set(deletedSchedulesInfo.map(s => s.projectName))].length} projects`,
        description: description,
        changes: changes,
        before: { bulk: true, schedules: originalSchedules.map(s => s.toObject()) },
        after: null,
        route: req.originalUrl || '/assigned-resources',
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()
      });
      
      res.json({ success: true, message: `Successfully deleted ${result.deletedCount} schedule(s)` });
    } else {
      res.status(404).json({ success: false, error: 'No schedules found or already deleted' });
    }
  } catch (err) {
    console.error('❌ Error in bulk delete assigned-resources:', err);
    console.error('❌ Stack trace:', err.stack);
    res.status(500).json({ success: false, error: err.message });
  }
});



// Admin: View Audit Logs (removed duplicate route - using main /audit-logs route with CSRF protection)

app.get('/employees/add', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const divisions = await Employee.distinct('division');
    const designations = await Employee.distinct('designation');
    const payrollCompanies = await Employee.distinct('payrollCompany');
const locations = await Employee.distinct('location');
const practices = await PracticeMaster.find();


    res.render('add-employee', {
      csrfToken: req.csrfToken(),
      title: 'Add Employee',
      divisions,
      designations,
      payrollCompanies,  // ✅ add this
      locations,  
      practices,
      errors: []
    });
  } catch (err) {
    console.error('Error loading add-employee form:', err);
    res.status(500).send('Failed to load form');
  }
});

// Add Employee Submission
app.post('/employees/add', isAuth, isAdmin, csrfProtection, async (req, res) => {
  const { empCode, name, payrollCompany, division, location, designation, homePractice, practiceManager } = req.body;
  const errors = [];

  if (!empCode || !name || !division || !designation || !homePractice) {
    errors.push('All required fields must be filled');
  }

  const existing = await Employee.findOne({ empCode });
  if (existing) {
    errors.push('Employee code already exists');
  }

  if (errors.length > 0) {
    const divisions = await Employee.distinct('division');
    const designations = await Employee.distinct('designation');
    const payrollCompanies = await Employee.distinct('payrollCompany');
    const locations = await Employee.distinct('location');
    const practices = await PracticeMaster.find();


    return res.render('add-employee', {
      csrfToken: req.csrfToken(),
      title: 'Add Employee',
      divisions,
       payrollCompanies, // ✅ add this
       locations,
      designations,
      practices,
      errors
    });
  }

  try {
    const newEmployee = await Employee.create({
      empCode,
      name,
      payrollCompany,
      division,
      location,
      designation,
      homePractice,
      practiceManager
    });

    // Admin audit logging for employee creation
    const description = `Admin ${req.session.user?.email} created employee: ${empCode} (${name}) via admin-add-employee`;
    const changes = {
      operation: 'admin_create_employee',
      employeeDetails: {
        empCode,
        name,
        payrollCompany,
        division,
        location,
        designation,
        homePractice,
        practiceManager
      }
    };
    await logAuditAction(req, 'create', null, null, newEmployee.toObject(), description, changes);

    res.redirect('/dashboard/admin/view-employees');
  } catch (err) {
    console.error('Error adding employee:', err);
    res.status(500).send('Failed to add employee');
  }
});

// Edit Employee GET
app.get('/employees/:id/edit', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const employee = await Employee.findOne({ empCode: req.params.id });
    if (!employee) return res.status(404).send('Employee not found');
    res.render('edit-employee', { employee, csrfToken: req.csrfToken() });
  } catch (err) {
    console.error('Edit GET Error:', err);
    res.status(500).send('Server error');
  }
});

// Edit Employee POST
app.post('/employees/:id/edit', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    // Get original employee data for audit logging
    const originalEmployee = await Employee.findOne({ empCode: req.params.id });
    
    const updatedEmployee = await Employee.findOneAndUpdate(
      { empCode: req.params.id },
      {
        empCode: req.body.empCode,
        name: req.body.name,
        payrollCompany: req.body.payrollCompany,
        division: req.body.division,
        location: req.body.location,
        designation: req.body.designation,
        homePractice: req.body.homePractice,
        practiceManager: req.body.practiceManager
      },
      { new: true }
    );
    
    // Admin audit logging for employee update
    if (originalEmployee && updatedEmployee) {
      const description = `Admin ${req.session.user?.email} updated employee: ${req.params.id} (${updatedEmployee.name}) via admin-edit-employee`;
      const changes = {
        operation: 'admin_update_employee',
        employeeDetails: {
          empCode: req.params.id,
          originalData: originalEmployee.toObject(),
          updatedData: updatedEmployee.toObject()
        }
      };
      await logAuditAction(req, 'update', null, originalEmployee.toObject(), updatedEmployee.toObject(), description, changes);
    }
    
    res.redirect('/dashboard/admin/view-employees');
  } catch (err) {
    console.error('Edit POST Error:', err);
    res.status(500).send('Error updating employee');
  }
});

// Delete Employee POST
app.post('/employees/:id/delete', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const empCode = req.params.id;
    
    // Get original employee data for audit logging
    const originalEmployee = await Employee.findOne({ empCode });
    
    if (!originalEmployee) {
      return res.status(404).send('Employee not found');
    }
    
    // Use cascade delete helper function
    const deleteResult = await cascadeDeleteEmployees([empCode], {
      adminEmail: req.session.user?.email,
      route: 'admin-delete-employee'
    });
    
    if (!deleteResult.success) {
      console.error('Cascade delete failed:', deleteResult.error);
      return res.status(500).send('Error deleting employee: ' + deleteResult.error);
    }
    
    // Admin audit logging for employee deletion
    const description = `Admin ${req.session.user?.email} deleted employee: ${empCode} (${originalEmployee.name}) and ${deleteResult.deletedSchedules} related schedule assignments via admin-delete-employee`;
    const changes = {
      operation: 'admin_delete_employee',
      employeeDetails: {
        empCode: empCode,
        deletedData: originalEmployee.toObject()
      },
      cascadeDetails: {
        deletedSchedulesCount: deleteResult.deletedSchedules,
        deletedSchedules: deleteResult.scheduleDetails
      }
    };
    await logAuditAction(req, 'delete', null, originalEmployee.toObject(), null, description, changes);
    
    console.log(`✅ Successfully deleted employee ${empCode} and ${deleteResult.deletedSchedules} related schedule assignments`);
    res.redirect('/dashboard/admin/view-employees');
  } catch (err) {
    console.error('Delete Employee Error:', err);
    res.status(500).send('Error deleting employee');
  }
});

// Check employee deletion dependencies (API endpoint for preview)
app.post('/employees/check-dependencies', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const { empCodes } = req.body;
    
    if (!empCodes || !Array.isArray(empCodes) || empCodes.length === 0) {
      return res.status(400).json({ success: false, message: 'No employee codes provided' });
    }
    
    const dependencies = await checkEmployeeDependencies(empCodes);
    
    res.json({
      success: true,
      dependencies: dependencies
    });
  } catch (err) {
    console.error('Error checking employee dependencies:', err);
    res.status(500).json({ success: false, message: 'Error checking dependencies' });
  }
});

// Bulk delete employees route
app.post('/employees/bulk-delete', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const { empCodes } = req.body;
    
    if (!empCodes || !Array.isArray(empCodes) || empCodes.length === 0) {
      return res.status(400).json({ success: false, message: 'No employee codes provided' });
    }
    
    // Get original employee data for audit logging
    const originalEmployees = await Employee.find({ empCode: { $in: empCodes } });
    
    if (originalEmployees.length === 0) {
      return res.status(404).json({ success: false, message: 'No employees found with provided codes' });
    }
    
    // Use cascade delete helper function
    const deleteResult = await cascadeDeleteEmployees(empCodes, {
      adminEmail: req.session.user?.email,
      route: 'admin-bulk-delete-employees'
    });
    
    if (!deleteResult.success) {
      console.error('Bulk cascade delete failed:', deleteResult.error);
      return res.status(500).json({ 
        success: false, 
        message: 'Error deleting employees: ' + deleteResult.error 
      });
    }
    
    // Admin audit logging for bulk employee deletion
    const employeeNames = originalEmployees.map(e => `${e.empCode} (${e.name})`).join(', ');
    const description = `Admin ${req.session.user?.email} bulk deleted ${deleteResult.deletedEmployees} employees: ${employeeNames} and ${deleteResult.deletedSchedules} related schedule assignments via admin-bulk-delete-employees`;
    const changes = {
      operation: 'admin_bulk_delete_employees',
      employeeDetails: {
        deletedCount: deleteResult.deletedEmployees,
        deletedEmployees: originalEmployees.map(e => ({
          empCode: e.empCode,
          name: e.name,
          deletedData: e.toObject()
        }))
      },
      cascadeDetails: {
        deletedSchedulesCount: deleteResult.deletedSchedules,
        deletedSchedules: deleteResult.scheduleDetails
      }
    };
    await logAuditAction(req, 'bulk_delete', null, originalEmployees.map(e => e.toObject()), null, description, changes);
    
    console.log(`✅ Successfully bulk deleted ${deleteResult.deletedEmployees} employees and ${deleteResult.deletedSchedules} related schedule assignments`);
    
    res.json({ 
      success: true, 
      message: `Successfully deleted ${deleteResult.deletedEmployees} employee(s) and ${deleteResult.deletedSchedules} related schedule assignments`,
      deletedCount: deleteResult.deletedEmployees,
      deletedSchedulesCount: deleteResult.deletedSchedules
    });
  } catch (err) {
    console.error('Error bulk deleting employees:', err);
    res.status(500).json({ success: false, message: 'Error deleting employees' });
  }
});

// Assign Project GET
app.get('/employees/:id/assign-project', isAuth, isAdmin, csrfProtection, async (req, res) => {
  const employee = await Employee.findOne({ empCode: req.params.id });
  if (!employee) return res.status(404).send('Employee not found');
  res.render('assign-project', { employee, csrfToken: req.csrfToken() });
});

// Assign Project POST
app.post('/employees/:id/assign-project', isAuth, isAdmin, csrfProtection, async (req, res) => {
  await Employee.findOneAndUpdate(
    { empCode: req.params.id },
    { project: req.body.project }
  );
  res.redirect('/assigned-resources');
});

// ✅ New: Dismiss Project POST
app.post('/employees/:id/dismiss-project', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    await Employee.findOneAndUpdate(
      { empCode: req.params.id },
      { project: '' }
    );
    res.redirect('/dashboard/admin/view-employees');
  } catch (err) {
    console.error('Dismiss Project Error:', err);
    res.status(500).send('Error dismissing project');
  }
});
// === 📅 Schedule Routes ===

// Schedule Form Page
app.get('/schedule', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const employees = await Employee.find();
    // Fetch projects with manager, CBSL client, and DIH client fields
    const projects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient');
    // Get unique home practices from employees
    const practices = [...new Set(employees.map(emp => emp.homePractice).filter(Boolean))];

    res.render('schedule', {
      employees,
      projects,
      practices,
      csrfToken: req.csrfToken(),
      title: 'Assign Schedule',
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error('Error loading schedule page:', err);
    res.status(500).send('Internal Server Error');
  }
});

// API to fetch employee by EmpCode
app.get('/api/employee/:empCode', async (req, res) => {
  try {
    const emp = await Employee.findOne({ empCode: req.params.empCode });
    if (!emp) return res.status(404).json({ error: 'Employee not found' });

    res.json({
      name: emp.name,
      payrollCompany: emp.payrollCompany,
      division: emp.division,
      project: emp.project,
      practice: emp.homePractice,
      practiceHead: emp.practiceManager
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});


// API to fetch project by name
app.get('/api/project/:projectName', async (req, res) => {
  try {
    const project = await ProjectMaster.findOne({ projectName: req.params.projectName });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// API to fetch practice by name
app.get('/api/practice/:practiceName', async (req, res) => {
  try {
    const practice = await PracticeMaster.findOne({ practiceName: req.params.practiceName });
    if (!practice) return res.status(404).json({ error: 'Practice not found' });

    res.json({
      practiceName: practice.practiceName,
      practiceManager: practice.practiceManager
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});


// For fetching a project by its ID
app.get('/api/project-by-id/:id', async (req, res) => {
  try {
    const project = await ProjectMaster.findById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(project);
  } catch (err) {
    console.error('Error fetching project by ID:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save assigned schedule

app.post('/schedule', isAuth, isAdmin, csrfProtection, async (req, res) => {
  
  try {
    const empCodes = Array.isArray(req.body.emp_ids) ? req.body.emp_ids : [req.body.emp_ids];
    const filteredEmpCodes = empCodes.filter(code => code?.trim());
    const startDate = new Date(req.body.start_date);
    const endDate = new Date(req.body.end_date);

    // Validate dates
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).send('Invalid start or end date. Please select valid dates.');
    }
    if (endDate < startDate) {
      return res.status(400).send('End date must be after start date.');
    }

    // Helper to get all dates in range, skipping weekends, in YYYY-MM-DD format
    function getDateKeysSkipWeekends(start, end) {
      const keys = [];
      let d = new Date(start);
      while (d <= end) {
        const dayOfWeek = d.getDay(); // 0=Sunday, 6=Saturday
        if (dayOfWeek !== 0 && dayOfWeek !== 6) { // Skip weekends
          const dateStr = d.toISOString().slice(0,10); // YYYY-MM-DD
          keys.push({ key: dateStr, dateObj: new Date(d) });
        }
        d.setDate(d.getDate() + 1);
      }
      return keys;
    }
    const dateKeys = getDateKeysSkipWeekends(startDate, endDate);

    // Helper to format date keys
    function formatDateKey(dateStr) {
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        const year = d.getFullYear();
        return `${day}-${monthName}-${year}`;
      }
      return dateStr;
    }

    // Support: single employee + multiple projects, multiple employees + single project, and multiple employees + multiple projects
    const projectIds = req.body['project_ids[]'] ? (Array.isArray(req.body['project_ids[]']) ? req.body['project_ids[]'] : [req.body['project_ids[]']]) : [];
    const hoursList = req.body['hours_list[]'] ? (Array.isArray(req.body['hours_list[]']) ? req.body['hours_list[]'] : [req.body['hours_list[]']]) : [];
    
    // Debug: Log the received data to understand the form submission
    console.log('🔍 Schedule route received data:', {
      empCodes: filteredEmpCodes,
      projectIds,
      hoursList,
      singleProjectId: req.body.project_id,
      singleHours: req.body.hours,
      employeeCount: filteredEmpCodes.length,
      projectCount: projectIds.length
    });
    
    // If both projectIds and hoursList are present, assign all selected employees to all selected projects
    if (projectIds.length && hoursList.length && projectIds.length === hoursList.length) {
      console.log('🔍 Taking path 1: Multiple projects per employee OR single project with project_ids[] format');
      
      // Check if this is a single project with multiple employees case
      const isSingleProject = projectIds.length === 1;
      const isMultipleEmployees = filteredEmpCodes.length > 1;
      
      if (isSingleProject && isMultipleEmployees) {
        console.log('🔍 Detected: Multiple employees → Single project (consolidation needed)');
        // Handle multiple employees to single project with consolidation
        const projectId = projectIds[0];
        const hours = Number(hoursList[0]) || 0;
        let employeeAudits = [];
        let assignmentIds = [];
        
        for (const empCode of filteredEmpCodes) {
          const employee = await Employee.findOne({ empCode });
          if (!employee) {
            console.warn('Employee not found:', empCode);
            continue;
          }
          
          // Over-allocation check for each day
          let overAllocated = false;
          let overAllocDetails = [];
          for (const { key: dateKey, dateObj } of dateKeys) {
            let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
            let existingTotal = 0;
            for (const sched of existingSchedules) {
              let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
              existingTotal += Number(dh) || 0;
            }
            let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectId });
            if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
              existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
            }
            let totalHours = existingTotal + hours;
            if (totalHours > 8) {
              overAllocated = true;
              overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
            }
          }
          if (overAllocated) {
            return res.redirect(`/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
          }
          
          const query = { employee: employee._id, project: projectId };
          let existingSchedule = await AssignedSchedule.findOne(query);
          let dailyHoursObj = {};
          if (existingSchedule && existingSchedule.dailyHours) {
            dailyHoursObj = { ...existingSchedule.dailyHours };
          }
          for (const { key: dateKey, dateObj } of dateKeys) {
            dailyHoursObj[formatDateKey(dateKey)] = hours;
          }
          
          const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
          const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
            $setOnInsert: { employee: employee._id, project: projectId },
            $set: { dailyHours: dailyHoursObj, startDate, endDate },
          }, { upsert: true, new: true });
          
          // Collect employee information for consolidated audit log
          employeeAudits.push({
            empCode: empCode,
            name: employee.name,
            action: existingSchedule ? 'updated' : 'created',
            previousSchedule: previousSchedule,
            updatedSchedule: updatedSchedule.toObject(),
            assignmentId: updatedSchedule._id
          });
          assignmentIds.push(updatedSchedule._id);
        }
        
        // Create consolidated audit log for all employees assigned to this project
        if (employeeAudits.length > 0) {
          const projectDoc = await ProjectMaster.findById(projectId);
          const employeeNames = employeeAudits.map(e => `${e.empCode} (${e.name})`).join(', ');
          const hasUpdates = employeeAudits.some(e => e.action === 'updated');
          const hasCreates = employeeAudits.some(e => e.action === 'created');
          
          let actionDescription = '';
          let auditAction = '';
          if (hasUpdates && hasCreates) {
            actionDescription = 'created/updated';
            auditAction = 'bulk_assign'; // Use valid enum value
          } else if (hasUpdates) {
            actionDescription = 'updated';
            auditAction = 'update';
          } else {
            actionDescription = 'created';
            auditAction = 'create';
          }
          
          const description = `Admin ${req.session.user?.email} ${actionDescription} assignment for ${employeeAudits.length} employees (${employeeNames}) on project ${projectDoc?.projectName || 'Unknown'} from ${startDate.toDateString()} to ${endDate.toDateString()} via admin-schedule`;
          
          const changes = {
            operation: 'admin_schedule_assignment_single_project_multiple_employees',
            projectDetails: { projectName: projectDoc?.projectName || 'Unknown' },
            employeesCount: employeeAudits.length,
            employeeDetails: employeeAudits.map(e => ({ empCode: e.empCode, name: e.name, action: e.action })),
            hours: hours,
            dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
            assignmentIds: assignmentIds
          };
          
          // Use the first assignment ID for the audit log, but include all IDs in changes
          await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
        }
        
      } else {
        console.log('🔍 Detected: Single employee → Multiple projects OR Multiple employees → Multiple projects');
        // Handle the original case: single employee with multiple projects OR multiple employees with multiple projects
      for (const empCode of filteredEmpCodes) {
        const employee = await Employee.findOne({ empCode });
        if (!employee) {
          console.warn('Employee not found:', empCode);
          continue;
        }
        // Over-allocation check for each day
        let overAllocated = false;
        let overAllocDetails = [];
        for (const { key: dateKey, dateObj } of dateKeys) {
          let newTotal = 0;
          for (let i = 0; i < projectIds.length; i++) {
            newTotal += Number(hoursList[i]) || 0;
          }
          let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
          let existingTotal = 0;
          for (const sched of existingSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
            existingTotal += Number(dh) || 0;
          }
          // Subtract hours for this employee/project for this day (if updating)
          for (let i = 0; i < projectIds.length; i++) {
            let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectIds[i] });
            if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
              existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
            }
          }
          let totalHours = existingTotal + newTotal;
          if (totalHours > 8) {
            overAllocated = true;
            overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
          }
        }
        if (overAllocated) {
          return res.redirect(`/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
        }
        // Save for each project and collect audit information
        let projectAudits = [];
        let assignmentIds = [];
        
        for (let i = 0; i < projectIds.length; i++) {
          const projectId = projectIds[i];
          const hours = Number(hoursList[i]) || 0;
          const query = { employee: employee._id, project: projectId };
          let existingSchedule = await AssignedSchedule.findOne(query);
          let dailyHoursObj = {};
          if (existingSchedule && existingSchedule.dailyHours) {
            dailyHoursObj = { ...existingSchedule.dailyHours };
          }
          for (const { key: dateKey, dateObj } of dateKeys) {
            dailyHoursObj[formatDateKey(dateKey)] = hours;
          }
          
          const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
          const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
            $setOnInsert: { employee: employee._id, project: projectId },
            $set: { dailyHours: dailyHoursObj, startDate, endDate },
          }, { upsert: true, new: true });
          
          // Collect project information for consolidated audit log
          const projectDoc = await ProjectMaster.findById(projectId);
          projectAudits.push({
            projectName: projectDoc?.projectName || 'Unknown',
            hours: hours,
            action: existingSchedule ? 'updated' : 'created',
            previousSchedule: previousSchedule,
            updatedSchedule: updatedSchedule.toObject(),
            assignmentId: updatedSchedule._id
          });
          assignmentIds.push(updatedSchedule._id);
        }
        
        // Create consolidated audit log for all projects assigned to this employee
        if (projectAudits.length > 0) {
          const projectNames = projectAudits.map(p => p.projectName).join(', ');
          const totalHours = projectAudits.reduce((sum, p) => sum + p.hours, 0);
          const hasUpdates = projectAudits.some(p => p.action === 'updated');
          const hasCreates = projectAudits.some(p => p.action === 'created');
          
          let actionDescription = '';
          let auditAction = '';
          if (hasUpdates && hasCreates) {
            actionDescription = 'created/updated';
            auditAction = 'bulk_assign'; // Use valid enum value
          } else if (hasUpdates) {
            actionDescription = 'updated';
            auditAction = 'update';
          } else {
            actionDescription = 'created';
            auditAction = 'create';
          }
          
          const description = `Admin ${req.session.user?.email} ${actionDescription} assignment for ${empCode} on ${projectAudits.length} projects (${projectNames}) from ${startDate.toDateString()} to ${endDate.toDateString()} via admin-schedule`;
          
          const changes = {
            operation: 'admin_bulk_schedule_assignment_multiple_projects',
            employeeDetails: { empCode: empCode, name: employee.name },
            projectsCount: projectAudits.length,
            projectDetails: projectAudits.map(p => ({ projectName: p.projectName, hours: p.hours, action: p.action })),
            totalHours: totalHours,
            dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
            assignmentIds: assignmentIds
          };
          
          // Use the first assignment ID for the audit log, but include all IDs in changes
          await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
        }
      }
      } // End of else block for original logic
    } else if (req.body.project_id && req.body.hours) {
      console.log('🔍 Taking path 2: Multiple employees with single project_id format');
      // Multiple employees: single project
      const projectId = req.body.project_id;
      const hours = Number(req.body.hours) || 0;
      let employeeAudits = [];
      let assignmentIds = [];
      
      for (const empCode of filteredEmpCodes) {
        const employee = await Employee.findOne({ empCode });
        if (!employee) {
          console.warn('Employee not found:', empCode);
          continue;
        }
        let overAllocated = false;
        let overAllocDetails = [];
        for (const { key: dateKey, dateObj } of dateKeys) {
          let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
          let existingTotal = 0;
          for (const sched of existingSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
            existingTotal += Number(dh) || 0;
          }
          let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectId });
          if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
            existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
          }
          let totalHours = existingTotal + hours;
          if (totalHours > 8) {
            overAllocated = true;
            overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
          }
        }
        if (overAllocated) {
          return res.redirect(`/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
        }
        const query = { employee: employee._id, project: projectId };
        let existingSchedule = await AssignedSchedule.findOne(query);
        let dailyHoursObj = {};
        if (existingSchedule && existingSchedule.dailyHours) {
          dailyHoursObj = { ...existingSchedule.dailyHours };
        }
        for (const { key: dateKey, dateObj } of dateKeys) {
          dailyHoursObj[formatDateKey(dateKey)] = hours;
        }
        
        const previousSchedule = existingSchedule ? existingSchedule.toObject() : null;
        const updatedSchedule = await AssignedSchedule.findOneAndUpdate(query, {
          $setOnInsert: { employee: employee._id, project: projectId },
          $set: { dailyHours: dailyHoursObj, startDate, endDate },
        }, { upsert: true, new: true });
        
        // Collect employee information for consolidated audit log
        employeeAudits.push({
          empCode: empCode,
          name: employee.name,
          action: existingSchedule ? 'updated' : 'created',
          previousSchedule: previousSchedule,
          updatedSchedule: updatedSchedule.toObject(),
          assignmentId: updatedSchedule._id
        });
        assignmentIds.push(updatedSchedule._id);
      }
      
      // Create consolidated audit log for all employees assigned to this project
      if (employeeAudits.length > 0) {
        const projectDoc = await ProjectMaster.findById(projectId);
        const employeeNames = employeeAudits.map(e => `${e.empCode} (${e.name})`).join(', ');
        const hasUpdates = employeeAudits.some(e => e.action === 'updated');
        const hasCreates = employeeAudits.some(e => e.action === 'created');
        
        let actionDescription = '';
        let auditAction = '';
        if (hasUpdates && hasCreates) {
          actionDescription = 'created/updated';
          auditAction = 'bulk_assign'; // Use valid enum value
        } else if (hasUpdates) {
          actionDescription = 'updated';
          auditAction = 'update';
        } else {
          actionDescription = 'created';
          auditAction = 'create';
        }
        
        const description = `Admin ${req.session.user?.email} ${actionDescription} assignment for ${employeeAudits.length} employees (${employeeNames}) on project ${projectDoc?.projectName || 'Unknown'} from ${startDate.toDateString()} to ${endDate.toDateString()} via admin-schedule`;
        
        const changes = {
          operation: 'admin_schedule_assignment_single_project_multiple_employees',
          projectDetails: { projectName: projectDoc?.projectName || 'Unknown' },
          employeesCount: employeeAudits.length,
          employeeDetails: employeeAudits.map(e => ({ empCode: e.empCode, name: e.name, action: e.action })),
          hours: hours,
          dateRange: `${startDate.toDateString()} to ${endDate.toDateString()}`,
          assignmentIds: assignmentIds
        };
        
        // Use the first assignment ID for the audit log, but include all IDs in changes
        await logAuditAction(req, auditAction, assignmentIds[0], null, null, description, changes);
      }
    }
    res.redirect('/calendar-view');
  } catch (error) {
    console.error('Error assigning schedule:', error);
    res.status(500).send('Something went wrong');
  }
});


// Calendar View Route
app.get('/calendar-view', isAuth, isAdmin, async (req, res) => {
  try {
    // Get filter params for month range
    const startMonthParam = req.query.startMonth;
    const endMonthParam = req.query.endMonth;

    let startYear, startMonth, endYear, endMonth;
    if (startMonthParam && endMonthParam) {
      const startParts = startMonthParam.split('-');
      const endParts = endMonthParam.split('-');
      startYear = parseInt(startParts[0], 10);
      startMonth = parseInt(startParts[1], 10);
      endYear = parseInt(endParts[0], 10);
      endMonth = parseInt(endParts[1], 10);
    } else {
      const now = new Date();
      startYear = now.getFullYear();
      startMonth = now.getMonth() + 1;
      endYear = now.getFullYear();
      endMonth = now.getMonth() + 1;
    }

    // Build query for AssignedSchedule (all schedules)
    const allSchedules = await AssignedSchedule.find()
      .populate('employee')
      .populate('project');

    // Generate dateRange for all working days between start and end month
    const dateRange = [];
    let currentYear = startYear;
    let currentMonth = startMonth;
    while (currentYear < endYear || (currentYear === endYear && currentMonth <= endMonth)) {
      const daysInMonth = new Date(currentYear, currentMonth, 0).getDate();
      for (let d = 1; d <= daysInMonth; d++) {
        const dateObj = new Date(currentYear, currentMonth - 1, d);
        // Include all days (including weekends) in calendar display
        const day = dateObj.getDate();
        const monthName = dateObj.toLocaleString('default', { month: 'short' });
        dateRange.push(`${day}-${monthName}-${currentYear}`);
      }
      if (currentMonth === 12) {
        currentMonth = 1;
        currentYear++;
      } else {
        currentMonth++;
      }
    }

    // Get all employees
    const allEmployees = await Employee.find({}, 'empCode name division designation homePractice practiceManager');


    // Build empDayProjects: { empCode: { date: [ { projectName, hours, projectId, assignmentId } ] } }
    const empDayProjects = {};
    allSchedules.forEach(s => {
      const empCode = s.employee?.empCode || 'N/A';
      if (!empDayProjects[empCode]) empDayProjects[empCode] = {};
      if (s.dailyHours && s.project && s.project.projectName) {
        Object.entries(s.dailyHours).forEach(([date, hours]) => {
          if (!empDayProjects[empCode][date]) empDayProjects[empCode][date] = [];
          empDayProjects[empCode][date].push({
            projectName: s.project.projectName,
            projectId: s.project._id,
            assignmentId: s._id,
            hours: Number(hours) || 0
          });
        });
      }
    });

    res.render('calendar-view', {
      startYear,
      startMonth,
      endYear,
      endMonth,
      dateRange,
      allEmployees,
      empDayProjects,
      layout: 'sidebar-layout',
      title: 'Resource Calendar View',
      user: req.session.user
    });
  } catch (err) {
    console.error('Error loading calendar view:', err);
    res.status(500).send('Internal Server Error');
  }
});


// (Place this at the end of the file, after all middleware and routes, but before app.listen)

// === AUDIT LOG ROUTES (Admin Only) ===

// View Admin and Manager Audit Logs
app.get('/audit-logs', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    
    // Filters
    const managerFilter = req.query.manager || '';
    const roleFilter = req.query.role || '';
    const actionFilter = req.query.action || '';
    const dateFrom = req.query.dateFrom || '';
    const dateTo = req.query.dateTo || '';
    
    let query = {};
    
    if (managerFilter) {
      query.manager = { $regex: managerFilter, $options: 'i' };
    }
    if (roleFilter) {
      query.userRole = roleFilter;
    }
    if (actionFilter) {
      query.action = actionFilter;
    }
    if (dateFrom || dateTo) {
      query.timestamp = {};
      if (dateFrom) query.timestamp.$gte = new Date(dateFrom);
      if (dateTo) query.timestamp.$lte = new Date(dateTo + 'T23:59:59');
    }
    
    const auditLogs = await AuditLog.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit);
    
    const totalLogs = await AuditLog.countDocuments(query);
    const totalPages = Math.ceil(totalLogs / limit);
    
    res.render('audit-logs', {
      auditLogs,
      currentPage: page,
      totalPages,
      totalLogs,
      managerFilter,
      roleFilter,
      actionFilter,
      dateFrom,
      dateTo,
      message: req.query.message || '',
      error: req.query.error || '',
      csrfToken: req.csrfToken(),
      title: 'Audit Logs',
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error('Error loading audit logs:', err);
    res.status(500).send('Error loading audit logs');
  }
});

// Revert Manager Action (Admin Only)
app.post('/audit-logs/:id/revert', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const { reason } = req.body;
    const result = await revertAuditLog(req.params.id, req.session.user.email, reason);
    
    if (result.success) {
      res.redirect('/audit-logs?message=' + encodeURIComponent('Action reverted successfully'));
    } else {
      res.redirect('/audit-logs?error=' + encodeURIComponent(result.error));
    }
  } catch (err) {
    console.error('Error reverting action:', err);
    res.redirect('/audit-logs?error=' + encodeURIComponent('Failed to revert action'));
  }
});

// API endpoint for manager calendar view updates (drag-and-drop)
app.post('/api/manager/update-assignment', isAuth, async (req, res) => {
  try {
    // Only allow managers to use this endpoint
    if (req.session.user?.role !== 'manager') {
      return res.status(403).json({ success: false, message: 'Access denied. Manager role required.' });
    }

    const { 
      assignmentId, 
      projectId, 
      oldEmpCode, 
      oldDate, 
      newEmpCode, 
      newDate, 
      hours, 
      projectName 
    } = req.body;

    // Find the source and target employees
    const oldEmployee = await Employee.findOne({ empCode: oldEmpCode });
    const newEmployee = await Employee.findOne({ empCode: newEmpCode });
    
    if (!oldEmployee) {
      return res.json({ success: false, message: `Source employee ${oldEmpCode} not found` });
    }
    if (!newEmployee) {
      return res.json({ success: false, message: `Target employee ${newEmpCode} not found` });
    }

    // Find the assignment schedule for the source employee
    let sourceSchedule = null;
    if (assignmentId) {
      sourceSchedule = await AssignedSchedule.findById(assignmentId).populate('project');
    }
    
    if (!sourceSchedule) {
      const schedules = await AssignedSchedule.find({ employee: oldEmployee._id }).populate('project');
      for (let sched of schedules) {
        if (sched.dailyHours && sched.dailyHours[oldDate] && parseFloat(sched.dailyHours[oldDate]) > 0) {
          sourceSchedule = sched;
          break;
        }
      }
    }

    if (!sourceSchedule || !sourceSchedule.dailyHours[oldDate]) {
      return res.json({ success: false, message: `No assignment found for ${oldEmpCode} on ${oldDate}` });
    }

    // Store original data for audit
    const originalSourceData = sourceSchedule.toObject();
    const originalHours = sourceSchedule.dailyHours[oldDate];

    // Remove hours from source date
    delete sourceSchedule.dailyHours[oldDate];
    sourceSchedule.markModified('dailyHours');
    
    // Find or create target schedule for the same project
    let targetSchedule = await AssignedSchedule.findOne({
      employee: newEmployee._id,
      project: sourceSchedule.project._id
    });

    let originalTargetData = null;
    if (targetSchedule) {
      originalTargetData = targetSchedule.toObject();
    }

    if (!targetSchedule) {
      targetSchedule = new AssignedSchedule({
        employee: newEmployee._id,
        project: sourceSchedule.project._id,
        practice: sourceSchedule.practice,
        dailyHours: {},
        role: sourceSchedule.role,
        startDate: sourceSchedule.startDate,
        endDate: sourceSchedule.endDate,
        scheduledBy: req.session.user?.email || 'Manager',
        scheduledAt: new Date()
      });
    }

    // Add hours to target date
    if (!targetSchedule.dailyHours) {
      targetSchedule.dailyHours = {};
    }
    targetSchedule.dailyHours[newDate] = parseFloat(hours);
    targetSchedule.markModified('dailyHours');

    // Save both schedules
    await sourceSchedule.save();
    await targetSchedule.save();

    // Audit logging for manager calendar view drag-and-drop
    const description = `${getUserRolePrefix(req)} moved ${originalHours}h assignment from ${oldEmpCode} (${oldDate}) to ${newEmpCode} (${newDate}) for project ${sourceSchedule.project?.projectName || 'Unknown'} via ${getRouteContext(req)} drag-and-drop`;
    const changes = {
      action: 'calendar-drag-drop',
      from: { employee: oldEmpCode, date: oldDate, hours: originalHours },
      to: { employee: newEmpCode, date: newDate, hours: hours },
      project: sourceSchedule.project?.projectName || 'Unknown'
    };
    await logAuditAction(req, 'update', targetSchedule._id, { 
      sourceScheduleBefore: originalSourceData,
      targetScheduleBefore: originalTargetData
    }, { 
      sourceScheduleAfter: sourceSchedule.toObject(),
      targetScheduleAfter: targetSchedule.toObject()
    }, description, changes);

    res.json({ 
      success: true, 
      message: `Successfully moved ${hours}h from ${oldEmpCode} to ${newEmpCode}` 
    });

  } catch (error) {
    console.error('Error in manager calendar update:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for manager to edit hours directly in calendar view
app.post('/api/manager/edit-hours', isAuth, async (req, res) => {
  try {
    // Only allow managers to use this endpoint
    if (req.session.user?.role !== 'manager') {
      return res.status(403).json({ success: false, message: 'Access denied. Manager role required.' });
    }

    const { empCode, date, projectId, oldHours, newHours } = req.body;

    // Find employee
    const employee = await Employee.findOne({ empCode });
    if (!employee) {
      return res.json({ success: false, message: 'Employee not found' });
    }

    // Find project
    const project = await ProjectMaster.findById(projectId);
    if (!project) {
      return res.json({ success: false, message: 'Project not found' });
    }

    // Find the schedule
    let schedule = await AssignedSchedule.findOne({ 
      employee: employee._id, 
      project: projectId 
    }).populate('project');

    if (!schedule) {
      return res.json({ success: false, message: 'Schedule not found' });
    }

    // Store original data for audit
    const originalSchedule = schedule.toObject();

    // Update hours
    if (parseFloat(newHours) === 0) {
      // Remove the date if hours are 0
      delete schedule.dailyHours[date];
    } else {
      // Update hours
      schedule.dailyHours[date] = parseFloat(newHours);
    }
    
    schedule.markModified('dailyHours');
    await schedule.save();

    // Audit logging for manager calendar view inline edit
    const description = `${getUserRolePrefix(req)} changed hours for ${empCode} on ${date} from ${oldHours}h to ${newHours}h for project ${project.projectName} via ${getRouteContext(req)} inline edit`;
    const changes = {
      action: 'calendar-inline-edit',
      employee: empCode,
      date: date,
      oldHours: oldHours,
      newHours: newHours,
      project: project.projectName
    };
    await logAuditAction(req, 'update', schedule._id, originalSchedule, schedule.toObject(), description, changes);

    res.json({ 
      success: true, 
      message: `Successfully updated hours for ${empCode} on ${date}` 
    });

  } catch (error) {
    console.error('Error in manager calendar edit hours:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for updating assignments via drag-and-drop
app.post('/api/update-assignment', isAuth, isAdmin, async (req, res) => {
  try {
    //console.log('Received assignment update request:', req.body);
    
    const { 
      assignmentId, 
      projectId, 
      oldEmpCode, 
      oldDate, 
      newEmpCode, 
      newDate, 
      hours, 
      projectName 
    } = req.body;

    // Find the source and target employees
    const oldEmployee = await Employee.findOne({ empCode: oldEmpCode });
    const newEmployee = await Employee.findOne({ empCode: newEmpCode });
    
    if (!oldEmployee) {
      return res.json({ success: false, message: `Source employee ${oldEmpCode} not found` });
    }
    if (!newEmployee) {
      return res.json({ success: false, message: `Target employee ${newEmpCode} not found` });
    }

    // Find the assignment schedule for the source employee
    let sourceSchedule = null;
    if (assignmentId) {
      sourceSchedule = await AssignedSchedule.findById(assignmentId).populate('project');
    }
    
    if (!sourceSchedule) {
      // Find by employee and check if has hours on the specific date
      const schedules = await AssignedSchedule.find({ employee: oldEmployee._id }).populate('project');
      for (let sched of schedules) {
        if (sched.dailyHours && sched.dailyHours[oldDate] && parseFloat(sched.dailyHours[oldDate]) > 0) {
          sourceSchedule = sched;
          break;
        }
      }
    }

    if (!sourceSchedule || !sourceSchedule.dailyHours[oldDate]) {
      return res.json({ success: false, message: `No assignment found for ${oldEmpCode} on ${oldDate}` });
    }

    // Remove hours from source date
    const originalHours = sourceSchedule.dailyHours[oldDate];
    delete sourceSchedule.dailyHours[oldDate];
    
    // Mark the field as modified for Mongoose
    sourceSchedule.markModified('dailyHours');
    
    // Find or create target schedule for the same project
    let targetSchedule = await AssignedSchedule.findOne({
      employee: newEmployee._id,
      project: sourceSchedule.project._id
    });

    if (!targetSchedule) {
      // Create new schedule for target employee
      targetSchedule = new AssignedSchedule({
        employee: newEmployee._id,
        project: sourceSchedule.project._id,
        practice: sourceSchedule.practice,
        dailyHours: {},
        role: sourceSchedule.role,
        startDate: sourceSchedule.startDate,
        endDate: sourceSchedule.endDate,
        scheduledBy: 'Drag-Drop System',
        scheduledAt: new Date()
      });
    }

    // Add hours to target date
    if (!targetSchedule.dailyHours) {
      targetSchedule.dailyHours = {};
    }
    targetSchedule.dailyHours[newDate] = parseFloat(hours);
    
    // Mark the field as modified for Mongoose
    targetSchedule.markModified('dailyHours');

    // Save both schedules
    await sourceSchedule.save();
    await targetSchedule.save();

    // Audit logging for drag-and-drop assignment changes (for both admin and manager)
    const description = `${getUserRolePrefix(req)} moved ${originalHours}h assignment from ${oldEmpCode} (${oldDate}) to ${newEmpCode} (${newDate}) for project ${sourceSchedule.project?.projectName || 'Unknown'} via ${getRouteContext(req)} drag-and-drop`;
    const changes = {
      action: 'drag-and-drop',
      from: { employee: oldEmpCode, date: oldDate, hours: originalHours },
      to: { employee: newEmpCode, date: newDate, hours: hours },
      project: sourceSchedule.project?.projectName || 'Unknown'
    };
    await logAuditAction(req, 'update', targetSchedule._id, { 
      oldAssignment: { employee: oldEmployee._id, date: oldDate, hours: originalHours },
      sourceSchedule: sourceSchedule.toObject()
    }, { 
      newAssignment: { employee: newEmployee._id, date: newDate, hours: hours },
      targetSchedule: targetSchedule.toObject()
    }, description, changes);

    //console.log('Assignment updated successfully');
    res.json({ 
      success: true, 
      message: `Successfully moved ${hours}h from ${oldEmpCode} to ${newEmpCode}` 
    });

  } catch (error) {
    console.error('Error updating assignment:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for drag-fill feature
app.post('/api/drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      sourceDate, 
      projectId,
      targetCells, 
      hours,
      projectName 
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    // Find the project to assign
    let project;
    if (projectId) {
      project = await ProjectMaster.findById(projectId);
      if (!project) {
        return res.json({ success: false, message: 'Project not found' });
      }
    } else {
      // Fallback: find project by name
      project = await ProjectMaster.findOne({ projectName });
      if (!project) {
        return res.json({ success: false, message: 'Project not found' });
      }
    }

    let updatedCells = 0;
    let failedCells = [];

    // Process each target cell
    for (const cell of targetCells) {
      const { empCode, date } = cell;
      
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode });
        if (!targetEmployee) {
          failedCells.push(`${empCode} (employee not found)`);
          continue;
        }

        // Check if employee already has assignments for this date (8 hour limit)
        const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
        let totalHoursOnDate = 0;
        
        existingSchedules.forEach(schedule => {
          if (schedule.dailyHours && schedule.dailyHours[date]) {
            totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
          }
        });
        
        if (totalHoursOnDate + parseFloat(hours) > 8) {
          failedCells.push(`${empCode} on ${date} (would exceed 8h limit: ${totalHoursOnDate}h + ${hours}h)`);
          continue;
        }

        // Find or create target schedule for the project
        let targetSchedule = await AssignedSchedule.findOne({
          employee: targetEmployee._id,
          project: project._id
        });

        if (!targetSchedule) {
          // Create new schedule
          targetSchedule = new AssignedSchedule({
            employee: targetEmployee._id,
            project: project._id,
            dailyHours: {},
            scheduledBy: 'Drag-Fill System',
            scheduledAt: new Date()
          });
        }

        // Add hours to target date
        if (!targetSchedule.dailyHours) {
          targetSchedule.dailyHours = {};
        }
        
        // If date already exists, add to existing hours, otherwise set new hours
        if (targetSchedule.dailyHours[date]) {
          targetSchedule.dailyHours[date] = parseFloat(targetSchedule.dailyHours[date]) + parseFloat(hours);
        } else {
          targetSchedule.dailyHours[date] = parseFloat(hours);
        }
        
        // Mark the field as modified for Mongoose
        targetSchedule.markModified('dailyHours');
        await targetSchedule.save();
        
        updatedCells++;
      } catch (cellError) {
        console.error(`Error processing cell ${empCode} ${date}:`, cellError);
        failedCells.push(`${empCode} on ${date} (processing error)`);
      }
    }

    let message = `Successfully filled ${updatedCells} cells with ${hours}h of "${project.projectName}"`;
    if (failedCells.length > 0) {
      message += `. Failed: ${failedCells.join(', ')}`;
    }

    //console.log(`Drag-fill completed: ${updatedCells} cells updated, ${failedCells.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedCells: updatedCells,
      failedCells: failedCells
    });

  } catch (error) {
    console.error('Error in drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for drag-fill calendar updates
app.post('/api/calendar-drag-fill', isAuth, async (req, res) => {
  try {
    const { updates } = req.body;
    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ success: false, error: 'No updates provided.' });
    }
    // For each update: { empCode, date, hours }
    for (const upd of updates) {
      const { empCode, date, hours } = upd;
      if (!empCode || !date) continue;
      // Find employee by empCode
      const employee = await Employee.findOne({ empCode });
      if (!employee) continue;
      // Find all schedules for this employee on this date
      const schedules = await AssignedSchedule.find({ employee: employee._id });
      let found = false;
      for (const sched of schedules) {
        if (sched.dailyHours && sched.dailyHours[date] !== undefined) {
          sched.dailyHours[date] = parseFloat(hours);
          await sched.save();
          found = true;
        }
      }
      // If not found in any schedule, update the first schedule (or create one if none exist)
      if (!found && schedules.length > 0) {
        schedules[0].dailyHours[date] = parseFloat(hours);
        await schedules[0].save();
      }
      // If no schedule exists, skip (or optionally create a new one)
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Error in /api/calendar-drag-fill:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// API endpoint for multi-project drag-fill feature
app.post('/api/multi-project-drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received multi-project drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      sourceDate, 
      projects,
      targetCells
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    let updatedCells = 0;
    let failedCells = [];

    // Process each target cell
    for (const cell of targetCells) {
      const { empCode, date } = cell;
      
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode });
        if (!targetEmployee) {
          failedCells.push(`${empCode} (employee not found)`);
          continue;
        }

        // Check total hours for the date
        const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
        let totalHoursOnDate = 0;
        
        existingSchedules.forEach(schedule => {
          if (schedule.dailyHours && schedule.dailyHours[date]) {
            totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
          }
        });

        // Calculate total hours for all projects
        const totalProjectHours = projects.reduce((sum, proj) => sum + parseFloat(proj.hours), 0);
        
        if (totalHoursOnDate + totalProjectHours > 8) {
          failedCells.push(`${empCode} on ${date} (would exceed 8h limit: ${totalHoursOnDate}h + ${totalProjectHours}h)`);
          continue;
        }

        // Process each project
        for (const projectData of projects) {
          const project = await ProjectMaster.findById(projectData.projectId);
          if (!project) {
            continue;
          }

          // Find or create target schedule for the project
          let targetSchedule = await AssignedSchedule.findOne({
            employee: targetEmployee._id,
            project: project._id
          });

          if (!targetSchedule) {
            targetSchedule = new AssignedSchedule({
              employee: targetEmployee._id,
              project: project._id,
              dailyHours: {},
              scheduledBy: 'Multi-Project Drag-Fill System',
              scheduledAt: new Date()
            });
          }

          // Add hours to target date
          if (!targetSchedule.dailyHours) {
            targetSchedule.dailyHours = {};
          }
          
          if (targetSchedule.dailyHours[date]) {
            targetSchedule.dailyHours[date] = parseFloat(targetSchedule.dailyHours[date]) + parseFloat(projectData.hours);
          } else {
            targetSchedule.dailyHours[date] = parseFloat(projectData.hours);
          }
          
          targetSchedule.markModified('dailyHours');
          await targetSchedule.save();
        }
        
        updatedCells++;
      } catch (cellError) {
        console.error(`Error processing cell ${empCode} ${date}:`, cellError);
        failedCells.push(`${empCode} on ${date} (processing error)`);
      }
    }

    let message = `Successfully filled ${updatedCells} cells with ${projects.length} projects`;
    if (failedCells.length > 0) {
      message += `. Failed: ${failedCells.join(', ')}`;
    }

    //console.log(`Multi-project drag-fill completed: ${updatedCells} cells updated, ${failedCells.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedCells: updatedCells,
      failedCells: failedCells
    });

  } catch (error) {
    console.error('Error in multi-project drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for row drag-fill feature
app.post('/api/row-drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received row drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      rowProjects,
      targetEmployees
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    let updatedEmployees = 0;
    let failedEmployees = [];

    // Process each target employee
    for (const targetEmpCode of targetEmployees) {
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode: targetEmpCode });
        if (!targetEmployee) {
          failedEmployees.push(`${targetEmpCode} (employee not found)`);
          continue;
        }

        let employeeUpdated = false;

        // Process each project and its dates from the source row
        for (const projectData of rowProjects) {
          const project = await ProjectMaster.findById(projectData.projectId);
          if (!project) {
            continue;
          }

          // Find or create target schedule for the project
          let targetSchedule = await AssignedSchedule.findOne({
            employee: targetEmployee._id,
            project: project._id
          });

          if (!targetSchedule) {
            targetSchedule = new AssignedSchedule({
              employee: targetEmployee._id,
              project: project._id,
              dailyHours: {},
              scheduledBy: 'Row Drag-Fill System',
              scheduledAt: new Date()
            });
          }

          // Copy all dates and hours for this project
          for (const [date, hours] of Object.entries(projectData.dates)) {
            // Check if adding these hours would exceed 8h limit for this date
            const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
            let totalHoursOnDate = 0;
            
            existingSchedules.forEach(schedule => {
              if (schedule.dailyHours && schedule.dailyHours[date] && schedule._id.toString() !== targetSchedule._id.toString()) {
                totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
              }
            });

            if (totalHoursOnDate + parseFloat(hours) <= 8) {
              if (!targetSchedule.dailyHours) {
                targetSchedule.dailyHours = {};
              }
              targetSchedule.dailyHours[date] = parseFloat(hours);
              employeeUpdated = true;
            }
          }

          if (employeeUpdated) {
            targetSchedule.markModified('dailyHours');
            await targetSchedule.save();
          }
        }
        
        if (employeeUpdated) {
          updatedEmployees++;
        }
      } catch (empError) {
        console.error(`Error processing employee ${targetEmpCode}:`, empError);
        failedEmployees.push(`${targetEmpCode} (processing error)`);
      }
    }

    // Audit logging for row drag-fill operation
    const description = `${getUserRolePrefix(req)} performed row drag-fill: copied all projects from ${sourceEmpCode} to ${updatedEmployees} employees via ${getRouteContext(req)}`;
    const changes = {
      action: 'row-drag-fill',
      sourceEmployee: sourceEmpCode,
      targetEmployees: targetEmployees,
      sourceProjects: rowProjects,
      successfulEmployees: updatedEmployees,
      failedEmployees: failedEmployees
    };
    await logAuditAction(req, 'bulk_assign', null, null, { 
      sourceEmpCode,
      targetEmployees,
      rowProjects,
      results: { updatedEmployees, failedEmployees }
    }, description, changes);

    let message = `Successfully copied row data to ${updatedEmployees} employees`;
    if (failedEmployees.length > 0) {
      message += `. Failed: ${failedEmployees.join(', ')}`;
    }

    //console.log(`Row drag-fill completed: ${updatedEmployees} employees updated, ${failedEmployees.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedEmployees: updatedEmployees,
      failedEmployees: failedEmployees
    });

  } catch (error) {
    console.error('Error in row drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for cell replace drag-fill - replaces entire cell content
app.post('/api/cell-replace-drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received cell-replace-drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      sourceDate, 
      sourceProjects,
      targetCells
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    // Validate source projects
    if (!sourceProjects || sourceProjects.length === 0) {
      return res.json({ success: false, message: 'No source projects provided' });
    }

    // Calculate total hours from source projects
    const totalSourceHours = sourceProjects.reduce((sum, project) => sum + parseFloat(project.hours || 0), 0);
    
    if (totalSourceHours > 8) {
      return res.json({ success: false, message: `Source projects total ${totalSourceHours}h which exceeds 8-hour limit` });
    }

    let updatedCells = 0;
    let failedCells = [];

    // Process each target cell
    for (const cell of targetCells) {
      const { empCode, date } = cell;
      
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode });
        if (!targetEmployee) {
          failedCells.push(`${empCode} (employee not found)`);
          continue;
        }

        // Step 1: Delete all existing assignments for this employee on this date
        const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
        
        for (const schedule of existingSchedules) {
          if (schedule.dailyHours && schedule.dailyHours[date]) {
            // Remove this date from the schedule
            delete schedule.dailyHours[date];
            schedule.markModified('dailyHours');
            
            // If no dates left in this schedule, delete the entire schedule
            const remainingDates = Object.keys(schedule.dailyHours);
            if (remainingDates.length === 0) {
              await AssignedSchedule.findByIdAndDelete(schedule._id);
            } else {
              await schedule.save();
            }
          }
        }

        // Step 2: Create new assignments for each source project
        for (const sourceProject of sourceProjects) {
          // Find the project
          const project = await ProjectMaster.findById(sourceProject.projectId);
          if (!project) {
            console.warn(`Project not found: ${sourceProject.projectId}`);
            continue;
          }

          // Create or find schedule for this project
          let targetSchedule = await AssignedSchedule.findOne({
            employee: targetEmployee._id,
            project: project._id
          });

          if (!targetSchedule) {
            // Create new schedule
            targetSchedule = new AssignedSchedule({
              employee: targetEmployee._id,
              project: project._id,
              dailyHours: {},
              scheduledBy: 'Cell Replace Drag-Fill System',
              scheduledAt: new Date()
            });
          }

          // Set hours for the target date
          if (!targetSchedule.dailyHours) {
            targetSchedule.dailyHours = {};
          }
          
          targetSchedule.dailyHours[date] = parseFloat(sourceProject.hours);
          targetSchedule.markModified('dailyHours');
          await targetSchedule.save();
        }
        
        updatedCells++;
      } catch (cellError) {
        console.error(`Error processing cell ${empCode} ${date}:`, cellError);
        failedCells.push(`${empCode} on ${date} (processing error)`);
      }
    }

    // Audit logging for cell replace drag-fill operation
    const description = `${getUserRolePrefix(req)} performed cell replace drag-fill: copied ${sourceProjects.length} projects (${totalSourceHours}h) from ${sourceEmpCode} (${sourceDate}) to ${updatedCells} cells via ${getRouteContext(req)}`;
    const changes = {
      action: 'cell-replace-drag-fill',
      sourceEmployee: sourceEmpCode,
      sourceDate: sourceDate,
      sourceProjects: sourceProjects,
      totalSourceHours: totalSourceHours,
      targetCells: targetCells,
      successfulCells: updatedCells,
      failedCells: failedCells
    };
    await logAuditAction(req, 'bulk_replace', null, null, {
      sourceEmpCode,
      sourceDate,
      sourceProjects,
      targetCells,
      results: { updatedCells, failedCells }
    }, description, changes);

    let message = `Successfully replaced ${updatedCells} cells with source cell content (${sourceProjects.length} projects, ${totalSourceHours}h total)`;
    if (failedCells.length > 0) {
      message += `. Failed: ${failedCells.join(', ')}`;
    }

    //console.log(`Cell replace drag-fill completed: ${updatedCells} cells updated, ${failedCells.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedCells: updatedCells,
      failedCells: failedCells
    });

  } catch (error) {
    console.error('Error in cell-replace-drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint to get all projects for dropdown
app.get('/api/projects', isAuth, async (req, res) => {
  try {
    const projects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient').sort({ projectName: 1 });
    res.json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// API endpoint to get all practices for filtering
app.get('/api/practices', isAuth, async (req, res) => {
  try {
    const practices = await PracticeMaster.find({}, 'practiceName practiceManager').sort({ practiceName: 1 });
    res.json(practices);
  } catch (error) {
    console.error('Error fetching practices:', error);
    res.status(500).json({ error: 'Failed to fetch practices' });
  }
});

// API endpoint to get current assignments for an employee on a specific date
app.get('/api/assignments/:empCode/:date', isAuth, async (req, res) => {
  try {
    const { empCode, date } = req.params;
    
    const employee = await Employee.findOne({ empCode });
    if (!employee) {
      return res.json([]);
    }
    
    const schedules = await AssignedSchedule.find({ employee: employee._id }).populate('project');
    const assignments = [];
    
    schedules.forEach(schedule => {
      if (schedule.dailyHours && schedule.dailyHours[date] && schedule.project) {
        assignments.push({
          assignmentId: schedule._id,
          projectId: schedule.project._id,
          projectName: schedule.project.projectName,
          hours: schedule.dailyHours[date]
        });
      }
    });
    
    res.json(assignments);
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

// API endpoint to check existing assignments for multiple employees across a date range
app.post('/api/check-assignments', isAuth, async (req, res) => {
  try {
    const { empCodes, startDate, endDate } = req.body;
    
    if (!empCodes || !Array.isArray(empCodes) || !startDate || !endDate) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }

    // Find all employees
    const employees = await Employee.find({ empCode: { $in: empCodes } });
    const employeeMap = {};
    employees.forEach(emp => {
      employeeMap[emp.empCode] = emp._id;
    });

    // Find all schedules for these employees
    const employeeIds = employees.map(emp => emp._id);
    const schedules = await AssignedSchedule.find({ 
      employee: { $in: employeeIds } 
    }).populate('project employee');

    // Generate date range with correct format, skipping weekends (same as schedule system)
    const start = new Date(startDate);
    const end = new Date(endDate);
    const dateRange = [];
    for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
      const dayOfWeek = d.getDay(); // 0=Sunday, 6=Saturday
      if (dayOfWeek !== 0 && dayOfWeek !== 6) { // Skip weekends
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        const year = d.getFullYear();
        const dateStr = `${day}-${monthName}-${year}`;
        dateRange.push(dateStr);
      }
    }

    // Calculate existing allocations
    const allocations = {};
    empCodes.forEach(empCode => {
      allocations[empCode] = {};
      dateRange.forEach(date => {
        allocations[empCode][date] = { totalHours: 0, assignments: [] };
      });
    });

    schedules.forEach(schedule => {
      if (schedule.employee && schedule.dailyHours) {
        const empCode = schedule.employee.empCode;
        if (allocations[empCode]) {
          Object.keys(schedule.dailyHours).forEach(date => {
            if (allocations[empCode][date]) {
              const hours = schedule.dailyHours[date] || 0;
              allocations[empCode][date].totalHours += hours;
              allocations[empCode][date].assignments.push({
                projectName: schedule.project ? schedule.project.projectName : 'Unknown',
                hours: hours
              });
            }
          });
        }
      }
    });

    // Debug logging (remove in production)
    //console.log('Date range:', dateRange);
    //console.log('Allocations for first employee:', allocations[empCodes[0]]);

    res.json(allocations);
  } catch (error) {
    console.error('Error checking assignments:', error);
    res.status(500).json({ error: 'Failed to check assignments' });
  }
});

// API endpoint to create new assignment (Admin only)
app.post('/api/assignments', isAuth, async (req, res) => {
  try {
    const { empCode, date, projectId, hours } = req.body;
    
    if (!empCode || !date || !projectId || !hours) {
      return res.json({ success: false, message: 'Missing required fields' });
    }
    
    if (hours <= 0 || hours > 8) {
      return res.json({ success: false, message: 'Hours must be between 0.5 and 8' });
    }
    
    // Find employee
    const employee = await Employee.findOne({ empCode });
    if (!employee) {
      return res.json({ success: false, message: 'Employee not found' });
    }
    
    // Find project
    const project = await ProjectMaster.findById(projectId);
    if (!project) {
      return res.json({ success: false, message: 'Project not found' });
    }
    
    // Check if employee already has assignments for this date (8 hour limit)
    const existingSchedules = await AssignedSchedule.find({ employee: employee._id });
    let totalHoursOnDate = 0;
    
    existingSchedules.forEach(schedule => {
      if (schedule.dailyHours && schedule.dailyHours[date]) {
        totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
      }
    });
    
    if (totalHoursOnDate + parseFloat(hours) > 8) {
      return res.json({ 
        success: false, 
        message: `Cannot exceed 8 hours per day. Current allocation: ${totalHoursOnDate}h. Available: ${8 - totalHoursOnDate}h` 
      });
    }
    
    // Find existing schedule for this employee and project, or create new one
    let schedule = await AssignedSchedule.findOne({
      employee: employee._id,
      project: project._id
    });
    
    if (!schedule) {
      schedule = new AssignedSchedule({
        employee: employee._id,
        project: project._id,
        dailyHours: {},
        scheduledBy: 'Calendar System',
        scheduledAt: new Date()
      });
    }
    
    // Add or update hours for the specific date
    if (!schedule.dailyHours) {
      schedule.dailyHours = {};
    }
    
    if (schedule.dailyHours[date]) {
      // Update existing hours
      schedule.dailyHours[date] = parseFloat(hours);
    } else {
      // Add new hours
      schedule.dailyHours[date] = parseFloat(hours);
    }
    
    schedule.markModified('dailyHours');
    const savedSchedule = await schedule.save();
    
    // Audit logging for manager calendar assignment creation
    const description = `${getUserRolePrefix(req)} created assignment: ${hours}h of ${project.projectName} to ${employee.name} (${employee.empCode}) on ${date} via ${getRouteContext(req)}`;
    const changes = {
      action: 'calendar-create',
      employee: { empCode: employee.empCode, name: employee.name },
      project: { projectName: project.projectName, projectId: project._id },
      date: date,
      hours: parseFloat(hours)
    };
    await logAuditAction(req, 'create', savedSchedule._id, null, savedSchedule.toObject(), description, changes);
    
    res.json({ 
      success: true, 
      message: `Successfully assigned ${hours}h of ${project.projectName} to ${employee.name} on ${date}` 
    });
    
  } catch (error) {
    console.error('Error creating assignment:', error);
    res.json({ success: false, message: 'Internal server error' });
  }
});

// API endpoint to update assignment (Admin only)
app.put('/api/assignments/:assignmentId', isAuth, async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { hours, date } = req.body;
    
    if (!hours || hours <= 0 || hours > 8) {
      return res.json({ success: false, message: 'Hours must be between 0.5 and 8' });
    }
    if (!date) {
      return res.json({ success: false, message: 'Date is required to update assignment.' });
    }
    
    const schedule = await AssignedSchedule.findById(assignmentId).populate('employee project');
    if (!schedule) {
      return res.json({ success: false, message: 'Assignment not found' });
    }
    
    // Store original data for audit logging
    const originalSchedule = schedule.toObject();
    const originalHours = schedule.dailyHours && schedule.dailyHours[date] ? schedule.dailyHours[date] : 0;
    
    if (!schedule.dailyHours) {
      schedule.dailyHours = {};
    }
    
    // Check total hours constraint for the specified date
    const employee = schedule.employee;
    const allSchedules = await AssignedSchedule.find({ employee: employee._id });
    let totalHoursOnDate = 0;
    
    allSchedules.forEach(sched => {
      if (sched.dailyHours && sched.dailyHours[date]) {
        if (sched._id.toString() !== assignmentId) {
          totalHoursOnDate += parseFloat(sched.dailyHours[date]);
        }
      }
    });
    
    if (totalHoursOnDate + parseFloat(hours) > 8) {
      return res.json({ 
        success: false, 
        message: `Cannot exceed 8 hours per day. Other assignments: ${totalHoursOnDate}h. Available: ${8 - totalHoursOnDate}h` 
      });
    }
    
    schedule.dailyHours[date] = parseFloat(hours);
    schedule.markModified('dailyHours');
    const updatedSchedule = await schedule.save();
    
    // Audit logging for manager calendar assignment update
    const description = `${getUserRolePrefix(req)} updated assignment for ${employee.name} (${employee.empCode}) on ${date}: ${originalHours}h → ${hours}h for project ${schedule.project.projectName} via ${getRouteContext(req)}`;
    const changes = {
      action: 'calendar-update',
      employee: { empCode: employee.empCode, name: employee.name },
      project: { projectName: schedule.project.projectName, projectId: schedule.project._id },
      date: date,
      hoursChanged: { from: originalHours, to: parseFloat(hours) }
    };
    await logAuditAction(req, 'update', assignmentId, originalSchedule, updatedSchedule.toObject(), description, changes);
    
    res.json({ 
      success: true, 
      message: `Successfully updated assignment to ${hours}h on ${date}` 
    });
    
  } catch (error) {
    console.error('Error updating assignment:', error);
    res.json({ success: false, message: 'Internal server error' });
  }
});

// API endpoint to delete assignment (Admin only)
app.delete('/api/assignments/:assignmentId', isAuth, async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { empCode, date } = req.body;
    
    const schedule = await AssignedSchedule.findById(assignmentId).populate('employee project');
    if (!schedule) {
      return res.json({ success: false, message: 'Assignment not found' });
    }
    
    // Store original data for audit logging
    const originalSchedule = schedule.toObject();
    const deletedHours = schedule.dailyHours && schedule.dailyHours[date] ? schedule.dailyHours[date] : 0;
    
    // Remove the specific date from dailyHours
    if (schedule.dailyHours && schedule.dailyHours[date]) {
      delete schedule.dailyHours[date];
      schedule.markModified('dailyHours');
      
      let auditDescription, auditAfter;
      
      // If no more dates are scheduled, delete the entire schedule
      if (Object.keys(schedule.dailyHours).length === 0) {
        await AssignedSchedule.findByIdAndDelete(assignmentId);
        auditDescription = `${getUserRolePrefix(req)} deleted assignment and removed entire schedule for ${schedule.employee.name} (${schedule.employee.empCode}) - ${deletedHours}h of ${schedule.project.projectName} on ${date} via ${getRouteContext(req)}`;
        auditAfter = null;
        
        res.json({ 
          success: true, 
          message: `Successfully deleted assignment and removed empty schedule` 
        });
      } else {
        const updatedSchedule = await schedule.save();
        auditDescription = `${getUserRolePrefix(req)} deleted assignment for ${schedule.employee.name} (${schedule.employee.empCode}) - ${deletedHours}h of ${schedule.project.projectName} on ${date} via ${getRouteContext(req)}`;
        auditAfter = updatedSchedule.toObject();
        
        res.json({ 
          success: true, 
          message: `Successfully removed assignment for ${date}` 
        });
      }
      
      // Audit logging for manager calendar assignment deletion
      const changes = {
        action: 'calendar-delete',
        employee: { empCode: schedule.employee.empCode, name: schedule.employee.name },
        project: { projectName: schedule.project.projectName, projectId: schedule.project._id },
        date: date,
        deletedHours: deletedHours
      };
      await logAuditAction(req, 'delete', assignmentId, originalSchedule, auditAfter, auditDescription, changes);
      
    } else {
      res.json({ success: false, message: 'Assignment for specified date not found' });
    }
    
  } catch (error) {
    console.error('Error deleting assignment:', error);
    res.json({ success: false, message: 'Internal server error' });
  }
});

app.get('/view-users', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const allUsers = await User.find({}, 'email role createdAt').sort({ createdAt: -1 });
    res.render('view-users', {
      csrfToken: req.csrfToken(),
      title: 'User Management',
      layout: 'sidebar-layout',
      users: allUsers
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.render('view-users', {
      csrfToken: req.csrfToken(),
      title: 'User Management',
      layout: 'sidebar-layout',
      users: []
    });
  }
});

// Project Allocation Report Routes
app.get('/api/projects/list', isAuth, async (req, res) => {
  try {
    const projects = await ProjectMaster.find({}, 'projectName _id').sort({ projectName: 1 });
    res.json({ success: true, projects });
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch projects' });
  }
});

// Project Allocation Report - Main Route
app.get('/project-allocation-report', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const { projectId, startDate, endDate, division, cbslClient } = req.query;
    
    // Get all projects for dropdown
    const projects = await ProjectMaster.find({}, 'projectName _id').sort({ projectName: 1 });
    
    // Get distinct divisions (dihClient) and CBSL clients for dropdowns
    const divisions = await ProjectMaster.distinct('dihClient').then(vals => vals.filter(v => v));
    const cbslClients = await ProjectMaster.distinct('cbslClient').then(vals => vals.filter(v => v));
    
    let reportData = null;
    let selectedProject = null;
    
    if (projectId) {
      selectedProject = await ProjectMaster.findById(projectId);
      
      // Build date range for report (default to current year if not specified)
      const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
      const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);
      
      // Aggregate data from AssignedSchedule collection
      const schedules = await AssignedSchedule.find({ project: projectId })
        .populate('employee', 'empCode name homePractice')
        .populate('project', 'projectName cbslClient dihClient')
        .populate('practice', 'practiceName');
      
      // Process the data to create pivot table structure
      reportData = processAllocationData(schedules, start, end);
    } else if (division || cbslClient) {
      // Filter projects based on division or cbslClient
      const projectFilter = {};
      if (division) projectFilter.dihClient = division;
      if (cbslClient) projectFilter.cbslClient = cbslClient;
      
      const filteredProjects = await ProjectMaster.find(projectFilter, '_id');
      const projectIds = filteredProjects.map(p => p._id);
      
      if (projectIds.length > 0) {
        // Build date range for report (default to current year if not specified)
        const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
        const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);
        
        // Aggregate data from AssignedSchedule collection for all filtered projects
        const schedules = await AssignedSchedule.find({ project: { $in: projectIds } })
          .populate('employee', 'empCode name homePractice')
          .populate('project', 'projectName cbslClient dihClient')
          .populate('practice', 'practiceName');
        
        // Process the data to create pivot table structure
        reportData = processAllocationData(schedules, start, end);
      }
    }
    
    const isManagerRole = req.session.user?.role === 'manager';
    
    res.render('project-allocation-report', {
      title: 'Project Allocation Report',
      layout: 'sidebar-layout',
      manager: isManagerRole,
      projects,
      divisions,
      cbslClients,
      selectedProject,
      reportData,
      selectedProjectId: projectId || '',
      selectedDivision: division || '',
      selectedCbslClient: cbslClient || '',
      startDate: req.query.startDate || '',
      endDate: req.query.endDate || '',
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    });
  } catch (error) {
    console.error('Error in project allocation report:', error);
    res.status(500).send('Error generating report');
  }
});

// Excel Export Route
app.get('/project-allocation-report/export/excel', isAuth, isAdmin, async (req, res) => {
  try {
    const { projectId, startDate, endDate, division, cbslClient } = req.query;
    
    // Ensure start/end are always defined for processing
    const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
    const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);

    let selectedProject = null;
    let schedules = [];
    
    if (projectId) {
      selectedProject = await ProjectMaster.findById(projectId);
      schedules = await AssignedSchedule.find({ project: projectId })
        .populate('employee', 'empCode name homePractice')
        .populate('project', 'projectName cbslClient dihClient')
        .populate('practice', 'practiceName');
    } else if (division || cbslClient) {
      const projectFilter = {};
      if (division) projectFilter.dihClient = division;
      if (cbslClient) projectFilter.cbslClient = cbslClient;
      
      const filteredProjects = await ProjectMaster.find(projectFilter, '_id');
      const projectIds = filteredProjects.map(p => p._id);
      
      if (projectIds.length > 0) {
        schedules = await AssignedSchedule.find({ project: { $in: projectIds } })
          .populate('employee', 'empCode name homePractice')
          .populate('project', 'projectName cbslClient dihClient')
          .populate('practice', 'practiceName');
      }
    } else {
      return res.status(400).send('Project ID, Division, or CBSL Client is required for export');
    }
    
    const reportData = processAllocationData(schedules, start, end);
    
    // Create Excel workbook
    const workbook = xlsx.utils.book_new();
    
    // Create worksheet data (FTE only per month)
    const worksheetData = [];

    // Header row: for each month include FTE, then Total FTE
    const headerRow = ['Practice'];
    reportData.months.forEach(month => {
      headerRow.push(`${month} (FTE)`);
    });
    headerRow.push('Total FTE');
    worksheetData.push(headerRow);

    // Data rows: push FTE for each month
    reportData.practices.forEach(practice => {
      const row = [practice.name];
      reportData.months.forEach(month => {
        const allocation = reportData.matrix[practice.name] && reportData.matrix[practice.name][month];
        const fte = allocation && (typeof allocation.fte !== 'undefined') ? allocation.fte : (reportData.monthWorkingHours && reportData.monthWorkingHours[month] ? Number(((allocation ? allocation.totalHours : 0) / reportData.monthWorkingHours[month]).toFixed(2)) : 0);
        row.push(fte);
      });
      row.push(practice.totalFTE || 0);
      worksheetData.push(row);
    });

    // Total row: per-month FTEs
    const totalRow = ['Total'];
    reportData.months.forEach(month => {
      totalRow.push(reportData.monthFTEs && typeof reportData.monthFTEs[month] !== 'undefined' ? reportData.monthFTEs[month] : (reportData.monthWorkingHours && reportData.monthWorkingHours[month] ? Number(((reportData.monthTotals[month]||0)/reportData.monthWorkingHours[month]).toFixed(2)) : 0));
    });
    totalRow.push(reportData.grandTotalFTE || 0);
    worksheetData.push(totalRow);
    
    const worksheet = xlsx.utils.aoa_to_sheet(worksheetData);
    xlsx.utils.book_append_sheet(workbook, worksheet, 'Project Allocation');
    
    // Generate buffer
    const buffer = xlsx.write(workbook, { type: 'buffer', bookType: 'xlsx' });
    
    // Set headers for download
    let filename = 'Allocation_Report';
    if (selectedProject) {
      filename = `${selectedProject.projectName}_Allocation_Report`;
    } else if (division && cbslClient) {
      filename = `${division}_${cbslClient}_Allocation_Report`;
    } else if (division) {
      filename = `${division}_Division_Allocation_Report`;
    } else if (cbslClient) {
      filename = `${cbslClient}_Client_Allocation_Report`;
    }
    filename += `_${new Date().toISOString().slice(0, 10)}.xlsx`;
    
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    
    res.send(buffer);
  } catch (error) {
    console.error('Error exporting to Excel:', error);
    res.status(500).send('Error exporting report');
  }
});

// PDF Export Route  
app.get('/project-allocation-report/export/pdf', isAuth, isAdmin, async (req, res) => {
  try {
    const { projectId, startDate, endDate, division, cbslClient } = req.query;
    
    let selectedProject = null;
    let schedules = [];
    let reportTitle = 'Project Allocation Report';
    
    if (projectId) {
      selectedProject = await ProjectMaster.findById(projectId);
      const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
      const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);
      
      schedules = await AssignedSchedule.find({ project: projectId })
        .populate('employee', 'empCode name homePractice')
        .populate('project', 'projectName cbslClient dihClient')
        .populate('practice', 'practiceName');
      
      reportTitle = `${selectedProject.projectName} - Allocation Report`;
    } else if (division || cbslClient) {
      const projectFilter = {};
      if (division) projectFilter.dihClient = division;
      if (cbslClient) projectFilter.cbslClient = cbslClient;
      
      const filteredProjects = await ProjectMaster.find(projectFilter, '_id');
      const projectIds = filteredProjects.map(p => p._id);
      
      if (projectIds.length > 0) {
        const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
        const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);
        
        schedules = await AssignedSchedule.find({ project: { $in: projectIds } })
          .populate('employee', 'empCode name homePractice')
          .populate('project', 'projectName cbslClient dihClient')
          .populate('practice', 'practiceName');
        
        if (division && cbslClient) {
          reportTitle = `${division} Division - ${cbslClient} Client - Allocation Report`;
        } else if (division) {
          reportTitle = `${division} Division - Allocation Report`;
        } else if (cbslClient) {
          reportTitle = `${cbslClient} Client - Allocation Report`;
        }
      }
    } else {
      return res.status(400).send('Project ID, Division, or CBSL Client is required for export');
    }
    
    const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
    const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);
    
    const reportData = processAllocationData(schedules, start, end);
    
    // Generate HTML content for PDF
    const htmlContent = generatePDFContent({ projectName: reportTitle }, reportData, start, end);
    
    // For now, we'll send HTML content. In production, you'd use a PDF library like puppeteer
    res.setHeader('Content-Type', 'text/html');
    res.send(htmlContent);
    
  } catch (error) {
    console.error('Error exporting to PDF:', error);
    res.status(500).send('Error exporting report');
  }
});

// Helper function to process allocation data into pivot table format
function processAllocationData(schedules, startDate, endDate) {
  const matrix = {};
  const practices = new Set();
  const monthsSet = new Set();
  const monthTotals = {};
  const monthWorkingHours = {}; // total working hours per month (weekdays * 8h)
  
  // Generate all months in the date range
  const months = [];
  const current = new Date(startDate.getFullYear(), startDate.getMonth(), 1);
  const endMonth = new Date(endDate.getFullYear(), endDate.getMonth(), 1);
  
  while (current <= endMonth) {
    const monthKey = current.toLocaleDateString('en-US', { year: 'numeric', month: 'short' });
    months.push(monthKey);
    monthsSet.add(monthKey);
    monthTotals[monthKey] = 0;
    monthWorkingHours[monthKey] = 0; // will compute below
    current.setMonth(current.getMonth() + 1);
  }

  // Compute working hours per month (assume 8 working hours per weekday, skip weekends).
  // If startDate/endDate constrain the first/last month, only count days within the range.
  function countWeekdaysInRange(year, monthIndex, rangeStart, rangeEnd) {
    const firstDay = new Date(year, monthIndex, 1);
    const lastDay = new Date(year, monthIndex + 1, 0);
    const start = rangeStart > firstDay ? rangeStart : firstDay;
    const end = rangeEnd < lastDay ? rangeEnd : lastDay;
    if (start > end) return 0;
    let count = 0;
    for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
      const day = d.getDay();
      if (day !== 0 && day !== 6) count++; // Mon-Fri
    }
    return count;
  }

  // Fill monthWorkingHours using months array
  months.forEach(monthKey => {
    // parse monthKey like "Jul 2024" or "Jul 2024" depending on locale; we created it using toLocaleDateString
    const parts = monthKey.split(' ');
    // parts: ["Jul", "2024"] or ["Jul", "2024"]
    const monthName = parts[0];
    const year = parseInt(parts[1], 10);
    const monthIndex = new Date(`${monthName} 1, ${year}`).getMonth();
    const weekdays = countWeekdaysInRange(year, monthIndex, new Date(startDate.getFullYear(), startDate.getMonth(), 1), new Date(endDate.getFullYear(), endDate.getMonth() + 1, 0));
    monthWorkingHours[monthKey] = weekdays * 8; // 8 hours per working day
  });
  
  // Process each schedule
  schedules.forEach(schedule => {
    const practice = schedule.employee?.homePractice || 'Unassigned';
    practices.add(practice);
    
    if (!matrix[practice]) {
      matrix[practice] = {};
    }
    
    // Process daily hours
    if (schedule.dailyHours) {
      Object.keys(schedule.dailyHours).forEach(dateKey => {
        const hours = Number(schedule.dailyHours[dateKey]) || 0;
        
        // Parse date key (format: "1-Jul-2024", "1-Aug-2025", or "2024-07-01")
        let dateObj;
        if (dateKey.includes('-') && dateKey.length > 8) {
          // Format: "1-Jul-2024" or "1-Aug-2025"
          const parts = dateKey.split('-');
          if (parts.length === 3) {
            const day = parseInt(parts[0]);
            const monthName = parts[1];
            const year = parseInt(parts[2]);
            const monthIndex = new Date(`${monthName} 1, 2000`).getMonth();
            dateObj = new Date(year, monthIndex, day);
          }
        } else if (dateKey.includes('-')) {
          // Format: "2024-07-01"
          dateObj = new Date(dateKey);
        }
        
        // More lenient date filtering - include dates that fall within the month range
        if (dateObj && isValidDate(dateObj)) {
          const monthKey = dateObj.toLocaleDateString('en-US', { year: 'numeric', month: 'short' });
          
          // Check if the date falls within our target months (regardless of exact start/end date)
          if (monthsSet.has(monthKey)) {
            // Additional check: ensure the date is within the general timeframe
            const isWithinRange = dateObj >= new Date(startDate.getFullYear(), startDate.getMonth(), 1) && 
                                 dateObj <= new Date(endDate.getFullYear(), endDate.getMonth() + 1, 0);
            
            if (isWithinRange) {
              if (!matrix[practice][monthKey]) {
                matrix[practice][monthKey] = { totalHours: 0, details: [], fte: 0 };
              }
              
              matrix[practice][monthKey].totalHours += hours;
              matrix[practice][monthKey].details.push({
                employee: schedule.employee?.name || 'Unknown',
                empCode: schedule.employee?.empCode || 'Unknown',
                date: dateKey,
                hours: hours
              });
              
              monthTotals[monthKey] += hours;
            }
          }
        }
      });
    }
  });
  
  // Convert practices set to array with totals
  const practicesArray = Array.from(practices).map(practiceName => {
    let totalHours = 0;
    months.forEach(month => {
      if (matrix[practiceName] && matrix[practiceName][month]) {
        totalHours += matrix[practiceName][month].totalHours;
      }
    });
    return {
      name: practiceName,
      totalHours: totalHours,
      totalFTE: 0 // will compute below
    };
  }).sort((a, b) => b.totalHours - a.totalHours);

  // Compute FTE values per cell, per month totals and per-practice totals
  const totalWorkingHoursAcrossRange = months.reduce((sum, m) => sum + (monthWorkingHours[m] || 0), 0) || 1;

  // per-month FTEs
  const monthFTEs = {};
  months.forEach(month => {
    const w = monthWorkingHours[month] || 1;
    monthFTEs[month] = Number(((monthTotals[month] || 0) / w).toFixed(2));
  });

  // per-cell and per-practice - UPDATED: Sum monthly FTEs instead of averaging across range
  practicesArray.forEach(pr => {
    let sumOfMonthlyFTEs = 0; // Sum of FTEs across months instead of total hours/range
    months.forEach(month => {
      if (matrix[pr.name] && matrix[pr.name][month]) {
        const alloc = matrix[pr.name][month];
        const w = monthWorkingHours[month] || 1;
        alloc.fte = Number((alloc.totalHours / w).toFixed(2));
        sumOfMonthlyFTEs += alloc.fte; // Add this month's FTE to the sum
      }
    });
    pr.totalFTE = Number(sumOfMonthlyFTEs.toFixed(2)); // Total is now sum of monthly FTEs
  });

  // Grand total FTE is now sum of monthly FTEs instead of average across range
  const grandTotalFTE = Number(Object.values(monthFTEs).reduce((sum, fte) => sum + fte, 0).toFixed(2));
  
  return {
    matrix,
    practices: practicesArray,
    months,
    monthTotals,
  monthWorkingHours,
  monthFTEs,
    grandTotal: Object.values(monthTotals).reduce((sum, val) => sum + val, 0)
  ,grandTotalFTE
  };
}

// Helper function to validate date objects
function isValidDate(date) {
  return date instanceof Date && !isNaN(date);
}

// Helper function to generate PDF content
function generatePDFContent(project, reportData, startDate, endDate) {
  const startStr = startDate.toLocaleDateString();
  const endStr = endDate.toLocaleDateString();
  // Provide a path/url for the logo. In production PDF generation (puppeteer) this will resolve
  const logoUrl = '/logo.jpg';

  const months = reportData.months || [];
  const practices = reportData.practices || [];

  // Build rows for practices
  const practiceRows = practices.map(practice => {
    const monthCells = months.map(month => {
      const allocation = reportData.matrix[practice.name] && reportData.matrix[practice.name][month];
      const fte = allocation && (typeof allocation.fte !== 'undefined')
        ? allocation.fte
        : (reportData.monthWorkingHours && reportData.monthWorkingHours[month]
            ? Number(((allocation ? allocation.totalHours : 0) / reportData.monthWorkingHours[month]).toFixed(2))
            : 0);
      return `<td class="num">${fte}</td>`;
    }).join('');

    return `<tr>
      <td class="practice-name">${escapeHtml(practice.name)}</td>
      ${monthCells}
      <td class="total"><strong>${practice.totalFTE || 0}</strong></td>
    </tr>`;
  }).join('');

  const totalRow = months.map(month => {
    const fte = reportData.monthFTEs && typeof reportData.monthFTEs[month] !== 'undefined'
      ? reportData.monthFTEs[month]
      : (reportData.monthWorkingHours && reportData.monthWorkingHours[month]
          ? Number(((reportData.monthTotals[month] || 0) / reportData.monthWorkingHours[month]).toFixed(2))
          : 0);
    return `<td class="num total-month">${fte}</td>`;
  }).join('');

  const generatedOn = new Date().toLocaleDateString();

  const html = `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Project Allocation Report</title>
    <style>
      /* Typography */
      @media print { body { -webkit-print-color-adjust: exact; } }
      :root { --accent: #0b6efd; --muted: #6b7280; --bg: #ffffff; }
      body { font-family: 'Helvetica Neue', Arial, sans-serif; margin: 0; background: var(--bg); color: #111827; }
      .container { max-width: 1100px; margin: 24px auto; padding: 20px 28px; }

      /* Header */
      .header { display: flex; align-items: center; gap: 16px; border-bottom: 1px solid #e6edf3; padding-bottom: 12px; }
      .logo { width: 84px; height: 84px; object-fit: contain; border-radius: 6px; background: #fff; padding: 6px; box-shadow: 0 1px 3px rgba(12,17,28,0.06); }
      .header-text { flex: 1; }
      .title { font-size: 20px; font-weight: 700; color: #0f172a; margin: 0 0 6px 0; }
      .meta { display: flex; gap: 12px; align-items: baseline; color: var(--muted); font-size: 13px; }
      .meta .project { font-weight: 600; color: #0b6efd; }

      /* Table */
      .table-wrap { margin-top: 18px; overflow-x: auto; }
      table { width: 100%; border-collapse: collapse; font-size: 13px; }
      thead th { text-align: center; background: linear-gradient(180deg,#f8fafc,#f1f5f9); color: #0f172a; font-weight: 700; padding: 10px 8px; border: 1px solid #e6edf3; }
      tbody td { padding: 10px 8px; border: 1px solid #e6edf3; }
      tbody tr:nth-child(odd) td { background: #ffffff; }
      tbody tr:nth-child(even) td { background: #fbfdff; }
      td.practice-name { text-align: left; font-weight: 600; color: #0f172a; }
      td.num, td.total, td.total-month { text-align: center; }
      tr.total-row { background: #f1f9ff; font-weight: 700; }

      /* Footer */
      .footer { margin-top: 18px; display:flex; justify-content:space-between; color: var(--muted); font-size: 12px; }

      /* Responsive small screens */
      @media (max-width: 640px) {
        .header { flex-direction: column; align-items: flex-start; gap: 8px; }
        .logo { width: 64px; height: 64px; }
        .meta { flex-direction: column; align-items: flex-start; gap: 4px; }
        table { font-size: 12px; }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <img src="${logoUrl}" alt="Logo" class="logo" />
        <div class="header-text">
          <h2 class="title">Project Allocation Report</h2>
          <div class="meta">
            <div><span class="muted"></span> <span class="project">${escapeHtml(project.projectName || 'All Projects')}</span></div>
            <div><span class="muted">Period:</span> ${escapeHtml(startStr)} — ${escapeHtml(endStr)}</div>
          </div>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="min-width:200px;">Practice</th>
              ${months.map(m => `<th>${escapeHtml(m)}<br><span style="font-weight:600;color:var(--muted);font-size:11px">(FTE)</span></th>`).join('')}
              <th>Total FTE</th>
            </tr>
          </thead>
          <tbody>
            ${practiceRows}
            <tr class="total-row">
              <td><strong>Total</strong></td>
              ${totalRow}
              <td><strong>${reportData.grandTotalFTE || 0}</strong></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="footer">
      
        <div>Printed on ${escapeHtml(generatedOn)}</div>
      </div>
    </div>
  </body>
  </html>`;

  return html;
}

// Small helper to escape HTML inside template values
function escapeHtml(str) {
  if (str === null || typeof str === 'undefined') return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  }

  app.get('/manager-report', isAuth, async (req, res) => {
  try {
    // Only managers may view this route
    if (req.session.user?.role !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { projectId, startDate, endDate, division, cbslClient } = req.query;

    // Get all projects for dropdown
    const projects = await ProjectMaster.find({}, 'projectName _id').sort({ projectName: 1 });

    // Get distinct divisions (dihClient) and CBSL clients for dropdowns
    const divisions = await ProjectMaster.distinct('dihClient').then(vals => vals.filter(v => v));
    const cbslClients = await ProjectMaster.distinct('cbslClient').then(vals => vals.filter(v => v));

    let reportData = null;
    let selectedProject = null;

    if (projectId) {
      selectedProject = await ProjectMaster.findById(projectId);
      const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
      const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);

      const schedules = await AssignedSchedule.find({ project: projectId })
        .populate('employee', 'empCode name homePractice')
        .populate('project', 'projectName cbslClient dihClient')
        .populate('practice', 'practiceName');

      reportData = processAllocationData(schedules, start, end);
    } else if (division || cbslClient) {
      const projectFilter = {};
      if (division) projectFilter.dihClient = division;
      if (cbslClient) projectFilter.cbslClient = cbslClient;

      const filteredProjects = await ProjectMaster.find(projectFilter, '_id');
      const projectIds = filteredProjects.map(p => p._id);

      if (projectIds.length > 0) {
        const start = startDate ? new Date(startDate) : new Date(new Date().getFullYear(), 0, 1);
        const end = endDate ? new Date(endDate) : new Date(new Date().getFullYear(), 11, 31);

        const schedules = await AssignedSchedule.find({ project: { $in: projectIds } })
          .populate('employee', 'empCode name homePractice')
          .populate('project', 'projectName cbslClient dihClient')
          .populate('practice', 'practiceName');

        reportData = processAllocationData(schedules, start, end);
      }
    }

    res.render('manager-report', {
      title: 'Manager Allocation Report',
      layout: 'sidebar-layout',
      projects,
      divisions,
      cbslClients,
      reportData,
      selectedProject,
      selectedProjectId: projectId || '',
      selectedDivision: division || '',
      selectedCbslClient: cbslClient || '',
      startDate: req.query.startDate || '',
      endDate: req.query.endDate || ''
    });
  } catch (error) {
    console.error('Error in manager report:', error);
    res.status(500).send('Error generating manager report');
  }
});
// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});
  // end of the file 
  
// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

