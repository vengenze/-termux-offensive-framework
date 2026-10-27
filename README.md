# Modular CLI Automation Framework

A modular Python and Bash application demonstrating centralized state management, task orchestration, and structured menu navigation.

## Overview

This application provides a terminal interface to orchestrate multiple sub-tasks. It decouples the user menu interface from the backend processing logic, using a central JSON file to persist application state across module executions.

## System Architecture

The framework consists of three primary layers:

1. Orchestration Layer (menu.sh)
   - Serves as the primary entry point.
   - Displays terminal menus and captures user choices.
   - Invokes specific standalone Python utilities based on user selection.

2. State Management (scan_results.json)
   - Acts as a local data store across application runs.
   - Preserves configuration parameters, target metadata, and operation logs.
   - Allows independent scripts to pass structured context without tight coupling.

3. Execution Modules (*.py)
   - Modular Python scripts designed to perform single, focused operations.
   - Read from and update the centralized state file.
   - Run independently via command-line arguments or interactive inputs.

## Project Structure

.
├── menu.sh               # Terminal menu driver (Bash)
├── scan_results.json     # Central state management storage
├── auto_exploit.py       # Autonomous pipeline execution runner
├── sql_dumper.py         # Specific module scanner/utility
├── rev_shell.py          # Network socket handler & payload module
└── access_console.py     # Interactive state visualizer / dashboard

## Core Concepts

### Modular Script Design
Each script within the system operates independently. By separating tasks into dedicated files, individual tools can be updated, tested, or replaced without breaking the overall interface or state tracking logic.

### Centralized State Passing
Instead of passing complex command-line arguments between scripts, modules write key-value structures to scan_results.json. Subsequent scripts read this JSON file to retrieve contextual data.

### Input Validation & Options Parsing
The driver menu handles default values for missing inputs to prevent execution errors when user input is omitted.

## Usage

Make the primary orchestrator executable and launch it:

chmod +x menu.sh
./menu.sh
