/*
 * Wazuh app - Module for CIS benchmark family titles
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

/*
 * Titles of the top-level sections ("families") of the CIS benchmarks behind
 * the SCA policies shipped with Wazuh 4.x, keyed by SCA `policy_id`. The family
 * of a check is the first level of its CIS recommendation number, so check
 * 1.1.1 belongs to family 1.
 *
 * Only titles confirmed for the benchmark each policy is built on are listed:
 * section names and numbering change between benchmark layouts, so a family
 * with no confirmed title is left out and shown by number only.
 */
// Keys are Wazuh SCA policy IDs and values are CIS headings, kept verbatim.
/* eslint-disable camelcase, max-len */
export const cisFamiliesFile: {
  [policyId: string]: { [family: string]: string };
} = {
  // CIS Benchmark for Alma Linux 10
  cis_alma_linux_10: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Alma Linux 8 Benchmark v2.0.0
  cis_alma_linux_8: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Benchmark for Alma Linux 9
  cis_alma_linux_9: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Amazon Linux Benchmark v2.1.0
  cis_amazon_linux_1: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Amazon Linux 2 Benchmark v2.0.0
  cis_amazon_linux_2: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0
  cis_amazon_linux_2023: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '6': 'System Maintenance',
  },
  // CIS Apache HTTP Server 2.4 Benchmark v1.5.0
  cis_apache: {
    '2': 'Minimize Apache Modules',
    '3': 'Principles, Permissions, and Ownership',
    '4': 'Apache Access Control',
    '5': 'Minimize Features, Content and Options',
    '7': 'SSL/TLS Configuration',
    '8': 'Information Leakage',
    '9': 'Denial of Service Mitigations',
    '10': 'Request Limits',
  },
  // CIS Apple macOS 10.11 Benchmark v1.1.0
  cis_apple_macos_10_11: {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Preferences',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
    '6': 'User Accounts and Environment',
  },
  // CIS Apple macOS 10.12 Benchmark v1.1.0
  cis_apple_macos_10_12: {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Preferences',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
    '6': 'User Accounts and Environment',
  },
  // CIS Apple macOS 10.13 Benchmark v1.0.0
  cis_apple_macos_10_13: {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Preferences',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
    '6': 'User Accounts and Environment',
  },
  // CIS Apple macOS 10.14 Benchmark v1.0.0
  cis_apple_macos_10_14: {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Preferences',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
    '6': 'User Accounts and Environment',
  },
  // CIS Apple macOS 10.15 Benchmark v1.1.0
  cis_apple_macos_10_15: {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Preferences',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
    '6': 'User Accounts and Environment',
  },
  // CIS Apple macOS 11.0 Big Sur Benchmark v2.1.0
  'cis_apple_macos_11.x': {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Preferences',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
    '6': 'User Accounts and Environment',
  },
  // CIS Apple macOS 12.0 Monterey Benchmark v1.1.0
  'cis_apple_macos_12.x': {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Preferences',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
    '6': 'User Accounts and Environment',
  },
  // CIS CentOS Linux 10 Benchmark
  cis_centos10_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS CentOS Linux 6 Benchmark v2.0.2
  cis_centos6_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS CentOS Linux 7 Benchmark v3.1.2
  cis_centos7_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS CentOS Linux 8 Benchmark v2.0.0
  cis_centos8_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS CentOS Linux 9 Benchmark
  cis_centos9_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Debian Linux 10 Benchmark v2.0.0
  cis_debian10: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Access, Authentication and Authorization',
    '5': 'Logging and Auditing',
    '6': 'System Maintenance',
  },
  // CIS Debian Linux 11 Benchmark v1.0.0
  cis_debian11: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // Center for Internet Security Debian Linux 12 Benchmark v1.1.0
  cis_debian12: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network',
    '4': 'Host Based Firewall',
    '5': 'Access Control',
    '6': 'Logging and Auditing',
    '7': 'System Maintenance',
  },
  // Center for Internet Security Debian Linux 13 Benchmark
  cis_debian13: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network',
    '4': 'Host Based Firewall',
    '5': 'Access Control',
    '6': 'Logging and Auditing',
    '7': 'System Maintenance',
  },
  // CIS Debian Linux 7 Benchmark v1.0.0
  cis_debian7: {
    '2': 'Filesystem Configuration',
    '3': 'Secure Boot Settings',
    '4': 'Additional Process Hardening',
    '5': 'OS Services',
    '6': 'Special Purpose Services',
    '7': 'Network Configuration and Firewalls',
    '8': 'Logging and Auditing',
    '9': 'System Access, Authentication and Authorization',
    '10': 'User Accounts and Environment',
    '11': 'Warning Banners',
    '12': 'Verify System File Permissions',
    '13': 'Review User and Group Settings',
  },
  // CIS Debian Linux 8 Benchmark v2.0.0
  cis_debian8: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Debian Linux 9 Benchmark v1.0.1
  cis_debian9: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS HP-UX 11i Benchmark v1.5.0
  cis_hpux: {
    '1': 'Recommendations',
  },
  // CIS HP-UX 11i Benchmark
  cis_hpux_bastille: {
    '1': 'Recommendations',
  },
  // CIS Microsoft IIS 10 Benchmark v1.1.1
  cis_iis_10: {
    '1': 'Basic Configurations',
    '2': 'Configure Authentication and Authorization',
    '3': 'ASP.NET Configuration Recommendations',
    '4': 'Request Filtering and Other Restriction Modules',
    '5': 'IIS Logging Recommendations',
    '6': 'FTP Requests',
    '7': 'Transport Encryption',
  },
  // CIS_Apple_macOS_13.0_Ventura_Benchmark_v1.1.0
  'cis_macOS_13.0_Ventura.yml': {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Settings',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
  },
  // CIS_Apple_macOS_14.0_Sonoma_Benchmark_v1.0.0
  'cis_macOS_14.0_Sonoma.yml': {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Settings',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
  },
  // CIS_Apple_macOS_15.0_Sequoia_Benchmark_v1.0.0
  'cis_macOS_15.Sequoia.yml': {
    '1': 'Install Updates, Patches and Additional Security Software',
  },
  // CIS_Apple_macOS_26.0_Tahoe_Benchmark_v1.0.0
  'cis_macOS_26.x.yml': {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'System Settings',
    '3': 'Logging and Auditing',
    '4': 'Network Configurations',
    '5': 'System Access, Authentication and Authorization',
  },
  // CIS MongoDB 3.6 Benchmark v1.0.0
  cis_mongodb: {
    '1': 'Installation and Patching',
    '2': 'Authentication',
    '3': 'Access Control',
    '4': 'Data Encryption',
    '5': 'Auditing',
    '6': 'Operating System Hardening',
  },
  // CIS Oracle MySQL Community Server 5.6 Benchmark v1.1.0
  cis_mysql_community: {
    '1': 'Operating System Level Configuration',
    '4': 'General',
    '6': 'Auditing and Logging',
    '7': 'Authentication',
    '9': 'Replication',
  },
  // CIS Oracle MySQL Enterprise Edition 5.6 Benchmark v1.1.0
  cis_mysql_enterprise: {
    '1': 'Operating System Level Configuration',
    '4': 'General',
    '6': 'Auditing and Logging',
    '7': 'Authentication',
    '9': 'Replication',
  },
  // CIS NGINX version 1.14.0 Benchmark v1.0.0
  cis_nginx1: {
    '2': 'Basic Configuration',
    '3': 'Logging',
    '4': 'Encryption',
    '5': 'Request Filtering and Restrictions',
  },
  // CIS Benchmark for Oracle Database 19c v1.0.0
  cis_oracle_database_19c: {
    '2': 'Oracle Parameter Settings',
    '3': 'Oracle Connection and Login Restrictions',
    '4': 'Users',
    '5': 'Privileges & Grants & ACLs',
    '6': 'Audit/Logging Policies and Procedures',
  },
  // Center for Internet Security Oracle Linux 10
  cis_oracle_linux_10: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // Center for Internet Security Oracle Linux 9 Benchmark v1.0.0
  cis_oracle_linux_9: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Benchmark for PostgreSQL 13
  cis_postgresql_13: {
    '1': 'Installation and Patches',
    '3': 'Logging Monitoring And Auditing',
    '4': 'User Access and Authorization',
    '6': 'PostgreSQL Settings',
    '8': 'Special Configuration Considerations',
  },
  // CIS Red Hat Enterprise Linux 10 Benchmark
  cis_rhel10_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Red Hat Enterprise Linux 5 Benchmark v2.2.0
  cis_rhel5_linux: {
    '1': 'Install Updates, Patches and Additional Security Software',
    '2': 'OS Services',
    '3': 'Special Purpose Services',
    '4': 'Network Configuration and Firewalls',
    '6': 'System Access, Authentication and Authorization',
    '9': 'System Maintenance',
  },
  // CIS Red Hat Enterprise Linux 6 Benchmark v2.1.0
  cis_rhel6_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Red Hat Enterprise Linux 7 Benchmark v3.1.1
  cis_rhel7_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Red Hat Enterprise Linux 8 Benchmark v2.0.0
  cis_rhel8_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Red Hat Enterprise Linux 9 Benchmark v1.0.0
  cis_rhel9_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Rocky Linux 8 Benchmark v1.0.0
  cis_rocky_linux_8: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Rocky Linux 9 Benchmark v1.0.0
  cis_rocky_linux_9: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Rocky Linux 10 Benchmark v1.0.0: its checks (CIS numbers and titles)
  // are identical to the Rocky Linux 9 v1.0.0 policy, so it uses those titles.
  cis_rocky_linux_10: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS SUSE Linux Enterprise 11 Benchmark v2.1.0
  cis_sles11_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS SUSE Linux Enterprise 12 Benchmark v2.1.0
  cis_sles12_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS SUSE Linux Enterprise 15 Benchmark v1.1.1
  cis_sles15_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS SUSE Linux Enterprise 16 Benchmark
  cis_sles16_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Benchmark for Oracle Solaris 11 v1.1.0
  cis_solaris11: {
    '2': 'Disable Unnecessary Services',
    '3': 'Kernel Tuning',
    '4': 'Auditing and Logging',
    '5': 'File/Directory Permissions/Access',
    '6': 'System Access, Authentication, and Authorization',
    '7': 'User Accounts and Environment',
    '8': 'Warning Banners',
    '9': 'System Maintenance',
  },
  // CIS Benchmark for Oracle Solaris 11.4 v1.0.0
  'cis_solaris11.4': {
    '2': 'Disable Unnecessary Services',
    '3': 'Kernel Tuning',
    '4': 'Auditing and Logging',
    '5': 'File/Directory Permissions/Access',
    '6': 'System Access, Authentication, and Authorization',
    '7': 'User Accounts and Environment',
    '8': 'Warning Banners',
    '9': 'System Maintenance',
  },
  // CIS Microsoft SQL Server 2012 Benchmark v1.5.0
  cis_sqlserver_2012: {
    '2': 'Surface Area Reduction',
    '3': 'Authentication and Authorization',
    '4': 'Password Policies',
    '5': 'Auditing and Logging',
    '6': 'Application Development',
  },
  // CIS Microsoft SQL Server 2014 Benchmark v1.4.0
  cis_sqlserver_2014: {
    '2': 'Surface Area Reduction',
    '3': 'Authentication and Authorization',
    '4': 'Password Policies',
    '5': 'Auditing and Logging',
    '6': 'Application Development',
  },
  // CIS Microsoft SQL Server 2016 Benchmark v1.3.0
  cis_sqlserver_2016: {
    '2': 'Surface Area Reduction',
    '3': 'Authentication and Authorization',
    '4': 'Password Policies',
    '5': 'Auditing and Logging',
    '6': 'Application Development',
  },
  // CIS Microsoft SQL Server 2017 Benchmark v1.1.0
  cis_sqlserver_2017: {
    '2': 'Surface Area Reduction',
    '3': 'Authentication and Authorization',
    '4': 'Password Policies',
    '5': 'Auditing and Logging',
    '6': 'Application Development',
  },
  // CIS Microsoft SQL Server 2019 Benchmark v1.1.0
  cis_sqlserver_2019: {
    '2': 'Surface Area Reduction',
    '3': 'Authentication and Authorization',
    '4': 'Password Policies',
    '5': 'Auditing and Logging',
    '6': 'Application Development',
  },
  // CIS Ubuntu Linux 14.04 LTS Benchmark v2.1.0
  'cis_ubuntu14-04': {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0
  'cis_ubuntu16-04': {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Ubuntu Linux 18.04 LTS Benchmark v2.1.0
  'cis_ubuntu18-04': {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
  // CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0
  'cis_ubuntu22-04': {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network',
    '4': 'Host Based Firewall',
    '5': 'Access Control',
    '6': 'Logging and Auditing',
    '7': 'System Maintenance',
  },
  // CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0
  'cis_ubuntu24-04': {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network',
    '4': 'Host Based Firewall',
    '5': 'Access Control',
    '6': 'Logging and Auditing',
    '7': 'System Maintenance',
  },
  // CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0
  cis_win10_enterprise: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
    '19': 'Administrative Templates (User)',
  },
  // CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0
  cis_win11_enterprise: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
  },
  // CIS Microsoft Windows Server 2012 (non-R2) Benchmark v3.0.0
  cis_win2012: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
  },
  // CIS Microsoft Windows Server 2012 R2 Benchmark v3.0.0
  cis_win2012r2: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
  },
  // CIS Microsoft Windows Server 2016 v2.0.0
  cis_win2016: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
  },
  // CIS Microsoft Windows Server 2019 Benchmark v2.0.0
  cis_win2019: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
  },
  // CIS Microsoft Windows Server 2022 Benchmark v2.0.0
  cis_win2022: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
  },
  // CIS Microsoft Windows Server 2025 Benchmark
  cis_win2025: {
    '1': 'Account Policies',
    '2': 'Local Policies',
    '5': 'System Services',
    '9': 'Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)',
    '17': 'Advanced Audit Policy Configuration',
    '18': 'Administrative Templates (Computer)',
  },
  // CIS Distribution Independent Linux Benchmark v2.0.0
  sca_distro_independent_linux: {
    '1': 'Initial Setup',
    '2': 'Services',
    '3': 'Network Configuration',
    '4': 'Logging and Auditing',
    '5': 'Access, Authentication and Authorization',
    '6': 'System Maintenance',
  },
};
/* eslint-enable camelcase, max-len */

const hasOwn = (object: object, key: string) =>
  Object.prototype.hasOwnProperty.call(object, key);

export const getCisFamilyTitle = (
  policyId: unknown,
  family: unknown,
): string | undefined => {
  if (typeof policyId !== 'string' || typeof family !== 'string') {
    return undefined;
  }
  if (!hasOwn(cisFamiliesFile, policyId)) {
    return undefined;
  }
  const families = cisFamiliesFile[policyId];

  return hasOwn(families, family) ? families[family] : undefined;
};
