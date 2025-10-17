#!/bin/bash

# Quick scan script for cybersecurity competition

echo "============================================="
echo "          STARTING QUICK SCAN"
echo "============================================="

# Print the current date and time
echo
echo "----------- CURRENT DATE AND TIME -----------"
date
echo

# List the last 5 logged-in users
echo "----------- LAST 5 LOGGED-IN USERS -----------"
last | head -n 5
echo

# Show all active listening network connections
echo "----------- ACTIVE LISTENING NETWORK CONNECTIONS -----------"
ss -tuln
echo

# List all running processes
echo "----------- RUNNING PROCESSES -----------"
ps aux
echo

# List all cron jobs for the current user
echo "----------- CURRENT USER'S CRON JOBS -----------"
crontab -l
echo

# Find all files in the /tmp directory modified in the last 10 minutes
echo "----------- FILES IN /tmp MODIFIED IN THE LAST 10 MINUTES -----------"
find /tmp -mmin -10
echo

echo "============================================="
echo "              QUICK SCAN COMPLETE"
echo "============================================="
