# rundeck_failover
Template Script to failover with two Rundeck instances

Assumptions:
* Runeck is deployed to multiple servers.  SSH is used to remotely operate on then. SSH keys are assumed to be setup between servers.
* Scripts assume a "war" deployment method, adjustments needed for rpm install.
* Depends on Ansible being installed on VM where script is ran to store DB Password.
   * A vault would be located at $ANSIBLE_HOME/group_vars/all/vault
* Assumes a Rundeck install with Maria DB.
* Rundeck instances are controlled through a systemd service.

Features:
* Writes logs and config to a NFS backup location.
* Uses lsyncd for near real-time copy of Rundeck logs to NFS.
* Copies configs from primary to secondary instance.
* Stops and starts rundeck instances.
