# Setu — System for Efficient Team Utilization

Setu ("System for Efficient Team Utilization") is a lightweight resource allocation and schedule management web application built with Node.js and Express. It helps managers and admins assign employees to projects, maintain master data for employees, projects and practices, and track changes via audit logs.

This repository (Resource-Allocation-Project) contains the server, views, utilities and scripts used by the Setu application.

## Key features

- Create / view / update / delete master records: Employees, Projects, Practices
- Assign employees to projects with per-day hours (dailyHours) and generate schedules
- Bulk upload support (XLSX) for master data (employees, projects, practices)
- Audit logging for assignment changes with revert support (admin)
- Simple role-based UI (admin and manager) using server-rendered EJS views

## Tech stack

- Node.js (CommonJS)
- Express
- EJS templating and express-ejs-layouts
- MongoDB with Mongoose
- Multer for file uploads
- xlsx for spreadsheet parsing
- dotenv for configuration
- date-fns, axios, bcryptjs and other utilities

Dependencies are declared in `package.json`.

## Quick start (development)

Prerequisites:

- Node.js (>=16 recommended)
- A running MongoDB instance or Atlas connection string

Steps (Windows PowerShell):

```powershell
cd <path-to>\setu
npm install
create a .env file with at least MONGODB_URI
Example .env content:
MONGODB_URI=mongodb+srv://<user>:<pass>@cluster0.example.mongodb.net/setu-db
PORT=3000(optional)
npm start
```

The app listens on the `PORT` environment variable (default port 3000). The `start` script runs `node app.js` as defined in `package.json`.

You can also run with `nodemon` for development:

```powershell
npx nodemon app.js
```

## Built-in demo credentials

The repository contains dummy users seeded in `app.js` for quick testing:

- Admin: `admin@cbsl.com` / `admin123` (role: admin)

There are commented manager accounts in `app.js` that you can enable or create proper users in the `User` collection.

## Environment variables

At minimum provide:

- `MONGODB_URI` — MongoDB connection string

## Project structure overview

- `app.js` — main Express app, routing, DB connect and core utilities
- `package.json` — dependencies and scripts
- `models/` — Mongoose models (AssignedSchedule, Employee, ProjectMaster, PracticeMaster, AuditLog, User)
- `views/` — EJS views for UI (admin/manager dashboards, upload pages, schedule views, partials)
- `public/` — static assets (stylesheets, client JS, images)
- `uploads/` — uploaded files stored by Multer


## Troubleshooting

- MongoDB connection failures: verify `MONGODB_URI` in `.env` and that your IP is whitelisted (Atlas) or DB is reachable locally.
- Missing uploads: ensure `uploads/` directory exists and has write permissions.
- If views render incorrectly, check that `ejs` and `express-ejs-layouts` are installed and that the `views/` files are present.


