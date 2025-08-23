# Overview

This is a Telegram Security Bot that provides real-time URL threat analysis for Telegram groups and chats. The bot automatically detects URLs in messages and scans them using URLScan.io and Cloudflare Radar APIs to identify potential security threats like phishing, malware, and suspicious domains. It features admin controls, configurable threat thresholds, rate limiting, and comprehensive logging.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Core Architecture Pattern
The bot follows a modular service-oriented architecture with clear separation of concerns:

- **Main orchestrator** (`main.py`) - Coordinates all components and handles bot lifecycle
- **Handler layer** - Processes different types of messages and commands (admin, user messages)
- **Service layer** - Encapsulates business logic for URL scanning, threat analysis, and admin management
- **Data layer** - SQLite database for persistence with connection pooling
- **Utility layer** - Shared components for logging, rate limiting, and URL detection

## Message Processing Flow
1. Messages are intercepted by handlers based on type (regular messages vs admin commands)
2. URLs are extracted using regex patterns and validated
3. Threat analysis combines results from multiple security APIs
4. Results are scored using weighted algorithms and compared against configurable thresholds
5. Responses are sent back to users with threat assessments

## Database Design
Uses SQLite with these main entities:
- `url_scans` - Stores scan results and threat scores
- `chat_settings` - Per-chat configuration (thresholds, auto-scan settings)
- `admin_permissions` - User permissions and roles
- `whitelist/blacklist` - URL filtering lists

## Security and Rate Limiting
- Token bucket algorithm for API rate limiting to prevent quota exhaustion
- Thread-safe operations with connection pooling
- Admin permission system with role-based access control
- Configurable threat scoring with multiple security intelligence sources

## Error Handling and Resilience
- Graceful degradation when APIs are unavailable
- Fallback threat analysis using URL structure patterns
- Comprehensive logging with rotation and different log levels
- Connection timeouts and retry mechanisms for external APIs

# External Dependencies

## Required APIs
- **Telegram Bot API** - Core bot functionality and message handling
- **URLScan.io API** - Primary URL scanning and threat detection service
- **Cloudflare Radar API** - Domain intelligence and threat reputation data

## Database
- **SQLite** - Local data persistence for scan results, settings, and admin data

## Python Libraries
- **telebot (pyTelegramBotAPI)** - Telegram bot framework
- **requests** - HTTP client for API communications
- **sqlite3** - Database operations (built-in)
- **threading** - Concurrent operations and rate limiting
- **asyncio** - Asynchronous operations for improved performance

## Configuration
All external service credentials and bot settings are managed through environment variables with fallback defaults, making the bot deployment-ready for various environments.