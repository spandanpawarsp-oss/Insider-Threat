🔐 Insider Threat Detection Using Activity Logs
A web-based security monitoring system designed to monitor user activity, maintain audit logs, and identify suspicious behavior patterns that may indicate insider threats.

React JavaScript HTML JSON Security

📌 Overview
Insider Threat Detection Using Activity Logs is a web-based security monitoring system designed to help organizations identify suspicious activities performed by users who already have legitimate access to organizational systems and data.

Unlike external attackers, insider threats can be difficult to detect because their activities may initially appear legitimate. The system addresses this challenge by continuously recording user activities and analyzing activity patterns to identify potentially abnormal behavior.

The project focuses on monitoring activities such as document uploads, document downloads, login patterns, and other user actions, creating an audit trail that can be reviewed for suspicious behavior.

🎯 Problem Statement
Insider threats are a major security concern for modern organizations.

Authorized users may misuse their access intentionally or unintentionally, potentially resulting in:

Unauthorized use of sensitive data
Unusual document downloads
Abnormal login patterns
Data misuse by authorized personnel
Difficulty detecting threats at an early stage
Traditional monitoring approaches may fail to identify suspicious internal behavior before significant damage occurs.

This project aims to provide a centralized system that monitors activity logs and identifies unusual patterns that could indicate an insider threat.

💡 Proposed Solution
The system provides a web-based platform with three primary capabilities:

1. 🌐 Web-Based System
An accessible web platform that can be deployed and managed from locations with internet connectivity.

2. 📝 Activity Logging
User activities are comprehensively recorded to create an audit trail that can be reviewed and analyzed.

3. 🚨 Risk Detection
The system identifies potentially suspicious activity through anomaly detection and flags unusual patterns or behaviors.

✨ Key Features
👤 User Management
User registration
User authentication
Login and logout
Secure session handling
📂 Activity Monitoring
The system records user actions such as:

Document uploads
Document downloads
Login activity
Other system interactions
These activities contribute to the system's audit trail.

🔍 Insider Threat Detection
The system analyzes recorded activities to identify potentially suspicious behavior, including:

Unusual download activity
Abnormal login patterns
Unusual user behavior
Suspicious activity can then be flagged for further investigation.

👨‍💼 Admin Dashboard
Administrators can access a centralized dashboard containing:

System overview
Risk analysis
Total users
Activity information
📊 Data Visualization
Charts and graphs provide visual representations of monitored activity and risk information, making patterns easier to understand.

📑 Data Export
The system provides functionality for generating/exporting data in Excel sheet format for further analysis and record keeping.

🏗️ System Architecture
User Flow
┌──────────────┐
│   Register   │
└──────┬───────┘
       ↓
┌──────────────┐
│    Login     │
└──────┬───────┘
       ↓
┌──────────────┐
│ Authenticate │
└──────┬───────┘
       ↓
┌──────────────────────┐
│ Perform User Actions │
│ Upload / Download    │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│    Activity Logs     │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│  Threat Detection    │
└──────────┬───────────┘
           ↓
┌──────────────┐
│    Logout    │
└──────────────┘
