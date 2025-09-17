- Let's be honest, transferring sensitive files over the network has always been a bit stressful. You have critical data that needs to be transferred from point A to point B. This tool aims to give you peace of mind by encrypting your files before they leave your system.

# Why You'll Actually Want to Use This

- AES-256-CBC encryption.
- Each file gets its own cryptographically secure key.
- Automatic secure deletion of source files (when you want it).
- Integrity verification that catches corruption before it becomes your problem.
- It is clear, Open source transparency.

# Prerequisites

- The tool relies on some common Linux utilities that you probably already have:

- OpenSSL.
- SSH/SCP.
- Standard Unix tools like find, shred, and realpath.

# Use

-  If you need to encrypt and transfer a single file:

        ./securetransfer.sh document.txt server:/backup/

- If you need to manage an entire directory (recursively):
  
        ./securetransfer.sh -r /sensitive/project_files server:/encrypted_backup/

- if you need to be communicative about what's happening

        ./securetransfer.sh -v important_file.pdf server:/secure_storage/

- if you need to delete the source files after a successful transfer

        ./securetransfer.sh -d confidential_report.docx server:/archives/

# More advanced use

 - If you need to use a specific remote user account:

       ./securetransfer.sh -u backup_service database_dump.sql server:/daily_backups/

- If the file is large, switch to rsync for better performance:

       ./securetransfer.sh -p rsync -t 120 massive_dataset.tar.gz server:/bulk_storage/

- If you need to process everything in a directory and clean up:

       ./securetransfer.sh -r -d -v /tmp/sensitive_exports server:/secure_vault/

# Common mistakes that can occur

- ***Connection refused or timeout errors, if this happens, do the following:***

- Verify SSH connectivity (ssh user@remote_host)
- Check firewall rules on both ends
- Confirm the remote path exists and is writable

- ***Command not found errors, if this happens, do the following:***
  
-  Install missing dependencies through your package manager
-  Check if OpenSSL supports AES-256-CBC using the command:
  
        openssl enc -ciphers | grep aes-256-cbc

- ***Large file handling, if this happens, do the following:***

- Consider using rsync protocol.
- Increase timeout for slower connections.
- Monitor available disk space on both ends.

- ***Permission denied, if this happens, do the following:***
- 
- Check file permissions on source files.
- Verify write permissions on remote destination.
- Ensure SSH keys are properly configured.

# Contributing 

- If you run into issues or have suggestions for improvement, contributions are welcome and If you discover security issues, please report them.
