# Personal File Vault – OSI-Layer Implementation Plan

This document describes the planned implementation of the Personal File Vault system using the **OSI model** as an organizing framework. Each layer maps directly to concrete technologies, configurations, and development tasks required to build the system.

The goal of this document is to provide a clear, structured roadmap for development while ensuring architectural consistency and security across all layers.

---

## Layer 1 – Physical Layer

**Purpose:** Underlying hardware and physical infrastructure.

### Implementation Plan
- The system will run on a **single Amazon EC2 virtual machine**.
- All physical hardware concerns (CPU, memory, disk, networking hardware) are abstracted by AWS.
- No custom physical networking or hardware configuration is required.

### Developer Notes
- Instance type should provide sufficient disk I/O for file uploads and backups.
- Storage should be provisioned with enough capacity for user files and encrypted backups.

---

## Layer 2 – Data Link Layer

**Purpose:** Local network framing and link-level communication.

### Implementation Plan
- Handled entirely by AWS virtual networking.
- No custom MAC-level logic is required.
- EC2 security groups function as the primary link-level access filter.

### Developer Tasks
- Allow inbound TCP 443 (HTTPS)
- Allow inbound TCP 22 (SSH, restricted)
- Deny all other inbound traffic

---

## Layer 3 – Network Layer

**Purpose:** IP addressing and routing.

### Implementation Plan
- Public IPv4 or DNS hostname for the EC2 instance
- Private interface for internal services
- No internal routing between multiple hosts

### Developer Tasks
- Bind PostgreSQL to localhost only
- Ensure no database ports are publicly exposed

---

## Layer 4 – Transport Layer

**Purpose:** Reliable data transport.

### Implementation Plan
- All communication uses **TCP**
- No UDP-based services are required

---

## Layer 5 – Session Layer

**Purpose:** Managing authenticated user sessions.

### Implementation Plan
- Application-managed sessions
- Sessions stored in PostgreSQL
- Sessions expire automatically

### Developer Tasks
- Create sessions table
- Implement session validation
- Handle logout and expiration

---

## Layer 6 – Presentation Layer

**Purpose:** Data formatting, encryption, and encoding.

### Implementation Plan
- TLS/SSL encryption for all traffic
- HTTPS-only access
- JSON for structured data
- multipart/form-data for file uploads

### Developer Tasks
- Configure Nginx TLS
- Redirect HTTP to HTTPS
- Enforce secure headers

---

## Layer 7 – Application Layer

**Purpose:** Core system functionality.

### Authentication
- Username/password authentication
- Password hashing (bcrypt or Argon2)
- TOTP MFA (RFC 6238)
- Encrypted TOTP secrets

### File Management
- Secure uploads
- Staging directory with chattr +i
- POSIX-based isolation

### Database
- PostgreSQL for all state
- Parameterized queries
- Encrypted sensitive fields

### Logging
- Syslog-based auditing
- logrotate for retention

### Backup
- Cron-based backups
- GPG encryption
- Tested restore process

---

## Development Order

1. OS hardening
2. PostgreSQL setup
3. Web app skeleton
4. Authentication + sessions
5. TOTP integration
6. File handling
7. Logging
8. Backups
9. UI refinement

---

## Design Philosophy

- Single-host deployment
- Minimal dependencies
- Defense in depth
- Security over scalability