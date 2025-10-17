#!/bin/bash
# initial_recon.sh

# Create a timestamped log file in the user's home directory
LOG_FILE=~/initial_recon_$(date +"%Y-%m-%d_%H-%M-%S").txt

# --- Function to write output to both the screen and the log file ---
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# --- Start of Script ---
log "=================================================="
log "Initial Linux System Reconnaissance"
log "Timestamp: $(date)"
log "=================================================="

log "\n[+] Basic System Information:"
log "Hostname: $(hostname)"
log "OS Info: $(cat /etc/os-release | grep PRETTY_NAME)"
log "Uptime: $(uptime -p)"

log "\n[+] Network Configuration and Listening Ports:"
log "$(ip a)"
log "\n--- Listening Ports (TCP/UDP) ---"
# ss is a modern replacement for netstat
log "$(ss -tulpn)"

log "\n[+] User Information:"
log "Currently Logged-in Users:"
log "$(who)"
log "\n--- All Local Users (from /etc/passwd) ---"
log "$(cat /etc/passwd | cut -d: -f1)"

log "\n[+] Currently Running Processes:"
log "$(ps aux)"

log "\n[+] Cron Jobs for All Users:"
# Scans for scheduled tasks, a common persistence method
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v '^#' | sed "s/^/Cron for $user: /"
done | tee -a "$LOG_FILE"


log "\n[+] SUID/SGID Files (Potential Privilege Escalation):"
# These files run with elevated permissions and are a target for attackers
log "$(find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null)"


log "\n=================================================="
log "Reconnaissance Complete. Log saved to $LOG_FILE"
log "=================================================="