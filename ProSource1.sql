/* DATABASE SECURITY RISK ASSESSMENT SCRIPT		      */
/* risk_assessment_main.sql			              */
/* Last Updated 23-Jan-2015			              */
/* 						              */
/* Be sure to run this script as 'sys as SYSDBA'              */
/*  CHANGE LOG
Version: 3.13
01 - modified object audit query to correct error in return values
02 - modified privilege query to recursively include role priviles
03 - modified OS checks to look for TNS POISON mitigation CVE-2012-1675
04 - added query to check for 05LOGON vulnerability issues in 11g CVE-2012-3137
05 - added query to check for usernames same as password
06 - added queries to show database info at start of script
07 - added legal disclaimer at start of script
08 - added test for ShellShock BASH Bug vulnerability
09 - added addtional option and policy tests for data redaction
10 - added check for OJVM mitigation patch CVE-2014-6546-7,CVE-2014-6545, CVE-2014-6453, CVE-2014-6450, CVE-2014-6537 
11 - added check to see what the HTTPPORT is for XDB/Apex
12 - modified queries on who has access to sensitive data to order by table instead of grantee
13 - added test for Dual Public privileges CVE-2015-0393
*/
PROMPT The Database Security Risk Overview script you are about to run gathers data 
PROMPT and information about your system.  This data and info, rmation is gathered for 
PROMPT the express purpose of identifying some areas of potential security risk that
PROMPT might provide an avenue for a successful penetration attempt, potentially
PROMPT contributing to data breach ("Purpose").  This script is not designed or guaranteed
PROMPT to identify all potential or possible security risks.
PROMPT 
PROMPT Prior to continuing with the execution of this script, you are strongly advised 
PROMPT to validate that the checksum for this script matches the information provided to 
PROMPT you by Oracle with the script.  If the checksum does NOT match that information, 
PROMPT please exit the script without continuing and contact your Oracle account representative 
PROMPT for assistance.  As with any script, you are also strongly advised to first
PROMPT execute the script in a non-production environment to validate that the script 
PROMPT does not negatively or adversely impact your system.

PROMPT The information and data gathered by this script includes, among other things, system 
PROMPT configuration data and information that a skilled attacker may be able to use to 
PROMPT attempt to penetrate, or to penetrate, your system. You should handle the scripts 
PROMPT output in accordance with your companys policy for dealing with sensitive data. You 
PROMPT remain solely responsible for your system, the data and information gathered by this 
PROMPT script, and the output of this script.  You are also solely responsible for the execution 
PROMPT of, and the effect and results of the execution of (including, without limitation, any 
PROMPT damage or data loss), this script.

PROMPT By continuing with the execution of this script, you consent to the use for the Purpose, 
PROMPT by Oracle, of the information and data gathered by the script.

PROMPT Press the <ENTER> key to continue with the execution of this script. Press <CTRL>-C
PROMPT to exit.
PROMPT
PAUSE
connect / as sysdba
alter session set nls_date_format="DD-MON-YYYY HH24:MI";
TTITLE "Database Security Risk Assessment (Main)"

set lines 250
set pages 66
set verif off
set trims on
set tab off
set escape on
set heading off
col host for a40
col table_name format a30
col object_name format a30
col privilege format a35
col account_status format a16
col default_tablespace format a15
col external_name format a25
col username format a22
col user_name format a22
col grantor format a22
col owner format a22
col object_type format a15
col object_name format a25
col object_schema format a22
col grantee format a27
col type_name format a25
col type_schema format a17
col policy_text format a50
col directory_path format a100
spool dbra_main_$ORACLE_SID.out

SELECT '********** Database Security Risk Assessment '||sysdate||' FOR DATABASE: '||name||' **********' FROM v$database;
set heading on
PROMPT ****TABLE OF CONTENTS****
PROMPT QUICK LOOK - QUICK LOOK - QUICK LOOK - QUICK LOOK
PROMPT -----Check for users with DBA privs
PROMPT -----Check for roles with DBA privs
PROMPT -----Check users with Create, Alter, OR Drop User privileges
PROMPT -----Check for users with Alter Session
PROMPT -----Database users with deadly system privileges assigned to them.
PROMPT -----Check for users with EXPORT FULL DATABASE
PROMPT -----Database users with deadly roles assigned to them.
PROMPT -----Security related initialization parameters
PROMPT -----Security related feature usage
PROMPT -----What is being audited in the database?
PROMPT -----List directories
PROMPT ROLES ROLES ROLES ROLES ROLES ROLES ROLES
PROMPT -----Roles in this database
PROMPT -----Count of System level privileges granted to roles
PROMPT -----System Privileges granted to roles
PROMPT -----OBJECT-level Privileges on SYS, SYSTEM, DVSYS, OR LBACSYS objects granted to roles
PROMPT -----EXECUTE privileges on sensitive packages granted to roles
PROMPT -----Users assigned to roles
PROMPT USERS USERS USERS USERS USERS USERS USERS
PROMPT -----Top Role Owners
PROMPT -----Number of Roles granted to users
PROMPT -----Roles granted to users
PROMPT -----Users with SYSTEM as default tablespace
PROMPT -----Users in this database
PROMPT -----Potential Root Kits - users not visible in DBA_USERS
PROMPT -----Users whose passwords never expire
PROMPT -----Users not subject to failed login limits
PROMPT -----Roles granted to users
PROMPT -----Count of System level privileges granted to users
PROMPT -----Object level Privileges on SYS, SYSTEM, OR DVSYS objects granted to users
PROMPT -----Object level Privileges on SYS *$ tables granted to users
PROMPT -----EXECUTE privileges on sensitive packages granted to users
PROMPT -----Sample Schemas in this database
PROMPT PUBLIC PUBLIC PUBLIC PUBLIC PUBLIC
PROMPT -----Roles Granted To Public
PROMPT -----System Privileges Granted To Public
PROMPT -----Object Privileges Granted To Public
PROMPT -----Column Privileges Granted To Public
PROMPT PASSWORDS PASSWORDS PASSWORDS PASSWORDS PASSWORDS
PROMPT -----Password file users
PROMPT -----Count of Password Profile Users
PROMPT -----List of Password Profiles
PROMPT -----List of Password Verify Functions
PROMPT -----List Resource Profiles
PROMPT -----Check for passwords in database links
PROMPT -----Check for 11g databases without 10g verifiers CVE-2012-3137
PROMPT -----Check for default passwords using rainbow table
PROMPT -----Check for default passwords using dba_users_with_defpwd
PROMPT -----Check for passwords that are the same as the user name
PROMPT OBJECTS OBJECTS OBJECTS
PROMPT -----Which constraints have been disabled
PROMPT -----Which tables have names columns names like password
PROMPT -----Which tables have names columns names like SSN
PROMPT -----Which tables have names columns names like credit card numbers
PROMPT LOGIN TRIGGERS LOGIN TRIGGERS LOGIN TRIGGERS
PROMPT -----Which logon triggers exist?
PROMPT VPD VPD VPD VPD VPD VPD VPD VPD VPD
PROMPT -----Which VPD policies exist?
PROMPT REDACTION REDACTION REDACTION REDACTION REDACTION
PROMPT -----Which Data Redaction policies exist?
PROMPT ENCRYPTION ENCRYPTION ENCRYPTION ENCRYPTION
PROMPT -----Encryption Wallet
PROMPT -----Encrypted Columns
PROMPT -----Encrypted Tablespaces
PROMPT -----Tables in Encrypted Tablespaces
PROMPT CONFIGURATION CONFIGURATION CONFIGURATION CONFIGURATION
PROMPT -----Listing of parameters
PROMPT -----Listing of Java Permissions
PROMPT NETWORKING NETWORKING NETWORKING
PROMPT -----Check for external procedures
PROMPT -----Check status of network permissions (11g)
PROMPT PATCHING PATCHING PATCHING
PROMPT -----Check for PSU/CPU
PROMPT -----Patchsets from sysman.mgmt$applied_patchsets
PROMPT -----Patches from sysman.mgmt.applied_patches
PROMPT -----Tests for specific vulnerabilities
PROMPT OS level checks
PROMPT -----Check for ShellShock BASH bug
PROMPT -----Check patches applied to the database
PROMPT -----Check file permissions
PROMPT -----Who runs Oracle Processes?
PROMPT -----Check for OS Users that can startup, shutdown AND admin Oracle Databases
PROMPT -----/etc/passwd
PROMPT -----/etc/group
PROMPT -----Check listener security level
PROMPT -----Default Listener Status
PROMPT -----SQLNET.ORA FROM ORACLE_HOME 
PROMPT -----SQLNET.ORA FROM TNS_ADMIN
PROMPT -----LISTENER.ORA FROM ORACLE_HOME 
PROMPT -----LISTENER.ORA FROM TNS_ADMIN
PROMPT -----Check DB Password File Permissions 
PROMPT -----Check network listeners
PROMPT -----Check VNC servers
PROMPT
PROMPT
PROMPT #######################################################################
PROMPT DATABASE INFORMATION - DATABASE INFORMATION - DATABASE INFORMATION
PROMPT #######################################################################
column name format a8
column log_mode format a12
column platform_name format a30
column guard_status format a10 heading Guard|Status
column dataguard_broker format a10 heading Dataguard|Broker
column flashback_on format a9 heading flashbank|on
column controlfile_type format a11 heading controlfile|type
select name, created, log_mode, platform_name, guard_status, DATAGUARD_BROKER, flashback_on, controlfile_type 
from v$database;
column name clear
column log_mode clear
column platform_name clear
column guard_status clear
column dataguard_broker clear
column flashback_on clear
column controlfile_type clear
PROMPT #######################################################################
PROMPT Database Version
PROMPT #######################################################################
column banner format a80 
select * from v$version;
column banner clear
PROMPT #######################################################################
PROMPT QUICK LOOK - QUICK LOOK - QUICK LOOK - QUICK LOOK
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT Check for users with DBA privs
PROMPT #######################################################################
SELECT a.grantee "GRANTEE", a.admin_option "ADMIN", a.default_role "DEFAULT", b.account_status "ACCOUNT_STATUS"
FROM dba_role_privs a, dba_users b
WHERE a.grantee=b.username
AND grantee NOT IN ('SYS','SYSTEM')
AND grantee NOT IN (SELECT role FROM dba_roles)
AND granted_role='DBA'
/
PROMPT #######################################################################
PROMPT Check for roles with DBA privs
PROMPT #######################################################################
SELECT * FROM dba_role_privs
WHERE grantee IN (SELECT role FROM dba_roles)
AND granted_role='DBA'
/
PROMPT #######################################################################
PROMPT Check users with Create, Alter, OR Drop User privileges
PROMPT #######################################################################
SELECT a.grantee "GRANTEE", a.privilege "PRIVILEGE", a.admin_option "ADMIN_OPTION", b.account_status "ACCOUNT_STATUS"
FROM dba_sys_privs a, dba_users b
WHERE (privilege LIKE '%DROP%USER'
      OR privilege LIKE '%ALTER%USER%'
      OR privilege LIKE '%CREATE%USER%')
AND grantee NOT IN ('IMP_FULL_DATABASE', 'DBA')
AND a.grantee=b.username
ORDER BY 4,1,2
/
PROMPT #######################################################################
PROMPT Check for users with Alter Session
PROMPT #######################################################################
SELECT a.grantee "GRANTEE", a.privilege "PRIVILEGE", a.admin_option "ADMIN_OPTION", b.account_status "ACCOUNT_STATUS"
FROM dba_sys_privs a, dba_users b
WHERE a.privilege = 'ALTER SESSION'
AND grantee <> 'DBA'
AND a.grantee=b.username
ORDER BY 4,1
/
PROMPT #######################################################################
PROMPT Database users with deadly system privileges assigned to them.
PROMPT #######################################################################
SELECT a.privilege "PRIVILEGE", a.grantee "GRANTEE", a.admin_option "ADMIN_OPTION", b.account_status "ACCOUNT_STATUS"
FROM dba_sys_privs a, dba_users b
WHERE  privilege IN ('SELECT ANY TABLE', 'INSERT ANY TABLE','UPDATE ANY TABLE','DELETE ANY TABLE','SELECT ANY DICTIONARY', 'CREATE ANY PROCEDURE',
                      'ALTER ANY PROCEDURE','CREATE ANY TRIGGER','ALTER ANY TRIGGER')
 AND   grantee NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'AQ_ADMINISTRATOR_ROLE', 'DBA', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE',
                       'OEM_MONITOR', 'CTXSYS', 'DBSNMP', 'IFSSYS','IFSSYS$CM', 'MDSYS', 'ORDPLUGINS', 'ORDSYS', 'TIMESERIES_DBA')
 AND a.grantee=b.username
 ORDER BY 4,1,2
/

PROMPT #######################################################################
PROMPT Check for users with EXPORT FULL DATABASE
PROMPT #######################################################################
SELECT a.grantee "GRANTEE",a.granted_role "GRANTED_ROLE",a.admin_option "ADMIN_OPTION", a.default_role "DEFAULT_ROLE", 
       NVL(b.account_status,'ROLE') "ACCOUNT_STATUS"
FROM dba_role_privs a, dba_users b
WHERE grantee NOT IN (SELECT grantee FROM dba_role_privs
                     WHERE grantee NOT IN (SELECT role FROM dba_roles)
                     AND granted_role='DBA')
AND granted_role IN ('EXP_FULL_DATABASE','DATAPUMP_EXP_FULL_DATABASE', 'DATAPUMP_EXP_FULL_DATABASE','DATAPUMP_IMP_FULL_DATABASE' )
AND grantee <> 'DBA'
AND a.grantee =b.username(+)
ORDER BY 5,1,2
/
PROMPT #######################################################################
PROMPT Database users with deadly roles assigned to them.
PROMPT #######################################################################
SELECT a.grantee "GRANTEE",a.granted_role "GRANTED_ROLE",a.admin_option "ADMIN_OPTION", a.default_role "DEFAULT_ROLE", 
       b.account_status "ACCOUNT_STATUS"
FROM   dba_role_privs a, dba_users b
WHERE  granted_role IN ('DBA', 'SELECTROLE','AQ_ADMINISTRATOR_ROLE',
                       'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE',
                       'OEM_MONITOR')
  AND  grantee NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'AQ_ADMINISTRATOR_ROLE',
                       'DBA', 'EXP_FULL_DATABASE', 'IMP_FULL_DATABASE',
                       'OEM_MONITOR', 'CTXSYS', 'DBSNMP', 'IFSSYS',
                       'IFSSYS$CM', 'MDSYS', 'ORDPLUGINS', 'ORDSYS',
                       'TIMESERIES_DBA')
  AND a.grantee=b.username
ORDER BY 5,1,2
/
PROMPT #######################################################################
PROMPT Security related initialization parameters
PROMPT #######################################################################
col parameter_value format a60
SELECT trim(name)||': '||value "PARAMETER_VALUE", isdefault 
FROM v$parameter 
WHERE name IN 
       ('_trace_files_public','O7_DICTIONARY_ACCESSIBILITY','audit_file_dest','audit_sys_operations','audit_trail','compatible',
        'dblink_encrypt_login','dispatchers', 'global_names','os_authent_prefix','os_roles','remote_listener','remote_login_passwordfile',
        'remote_os_authent','remote_os_roles','sec_case_sensitive_logon','sec_protocol_error_trace_action','sec_protocol_error_further_action',
        'sec_max_failed_login_attempts','sec_return_server_release_banner','sql92_security','transaction_auditing','utl_file_dir')
ORDER BY 1;
PROMPT
PROMPT XDB Port is:
select dbms_xdb.gethttpport() from dual;
PROMPT #######################################################################
PROMPT Security related feature usage
PROMPT #######################################################################
col host for a40
col table_name format a30
col object_name format a30
col privilege format a35
col account_status format a16
col default_tablespace format a15
col external_name format a25
col username format a22
col user_name format a22
col grantor format a22
col owner format a22
col object_type format a15
col object_name format a25
col object_schema format a22
col grantee format a27
col type_name format a25
col type_schema format a17
col policy_text format a50
col directory_path format a100		
col name format a45
col version format a15
SELECT name, version, detected_usages,currently_used 
FROM dba_feature_usage_statistics
WHERE name in ('ASO native encryption and checksumming','Audit Options','Client Identifier','Data Masking Pack','Data Redaction', 'Encrypted Tablespaces','Label Security','Oracle Database Vault','Oracle Java Virtual Machine (system)','Oracle Java Virtual Machine (user)','Oracle Secure Backup','Read Only Tablespace','SecureFile Encryption (system)','SecureFile Encryption (user)','Transparent Data Encryption','Virtual Private Database (VPD)')
ORDER by 1,2;
PROMPT #######################################################################
PROMPT
PROMPT What is being audited in the database?
PROMPT
PROMPT #######################################################################
PROMPT ### Statement Audit
col proxy_name format a30
col audit_option format a40
col success format a15
col failure format a15
SELECT * FROM dba_stmt_audit_opts ORDER BY 1,3;
PROMPT ### Object Audit
select owner, object_type, object_name, sel, upd, ins, del, exe, alt from dba_obj_audit_opts order by 1,2,3;
PROMPT ### Privilege Audit
SELECT * FROM dba_priv_audit_opts;
PROMPT ### Fine Grained Audit Policies
SELECT object_schema, object_name, policy_name, policy_text, policy_column, enabled, sel, ins, upd, del FROM dba_audit_policies ORDER BY 1,2;
PROMPT #### What is in the audit trail 
select audit_type, count(*) "NUM", trunc(min(extended_timestamp)) "MIN_DATE", trunc(max(extended_timestamp)) "MAX_DATE"
from dba_common_audit_trail
group by audit_type;
PROMPT #######################################################################
PROMPT List directories
PROMPT #######################################################################
PROMPT -- Variables gathered using DBMS_SYSTEM
set serveroutput on
declare
v_oh varchar2(500);
v_tns varchar2(500);
v_path varchar2(4000);
begin
dbms_system.get_env('ORACLE_HOME',v_oh);
dbms_system.get_env('TNS_ADMIN',v_tns);
dbms_system.get_env('PATH',v_path);
dbms_output.put_line('ORACLE_HOME: '||v_oh);
dbms_output.put_line('TNS_ADMIN: '||v_tns);
dbms_output.put_line('PATH: '||v_path);
end;
/
PROMPT -- Variables gathered using audit_file_dest
SELECT trim(name)||': '||value "PARAMETER_VALUE", isdefault 
FROM v$parameter 
WHERE name = 'audit_file_dest';
PROMPT -- Variables gathered using a host-level echo of the variables
spool off
host echo ORACLE_HOME=$ORACLE_HOME  >> dbra_main_$ORACLE_SID.out
host echo TNS_ADMIN=$TNS_ADMIN  >> dbra_main_$ORACLE_SID.out
host echo PATH=$PATH  >> dbra_main_$ORACLE_SID.out
col directory_name format a30
col directory_path format a45
spool dbra_main_$ORACLE_SID.out append
SELECT * FROM dba_directories ORDER BY owner, directory_path
/
select * from dba_tab_privs where exists (select 'XX' from dba_directories where directory_name = table_name)
/
PROMPT #######################################################################
PROMPT ROLES ROLES ROLES ROLES ROLES ROLES ROLES
PROMPT #######################################################################
PROMPT
PROMPT Roles in this database
PROMPT
PROMPT #######################################################################
col role format a45
SELECT * FROM dba_roles ORDER BY 1;
PROMPT #######################################################################
PROMPT
PROMPT Count of System level privileges granted to roles
PROMPT
PROMPT #######################################################################
col grantee format a30
 select count(*) "COUNT_SYSPRIVS" , grantee "ROLE_NAME"
  from dba_sys_privs a, DBA_roles b
  where b.role = a.grantee
 group by grantee
 order by 1 desc;
col grantee clear
PROMPT #######################################################################
PROMPT
PROMPT System Privileges granted to roles
PROMPT
PROMPT #######################################################################
col ROLE_NAME format a30
SELECT grantee "ROLE_NAME", privilege, admin_option FROM dba_sys_privs WHERE grantee in
   (SELECT role FROM dba_roles) ORDER BY grantee, privilege
/
PROMPT #######################################################################
PROMPT
PROMPT OBJECT-level Privileges on SYS, SYSTEM, DVSYS, OR LBACSYS objects granted to roles
PROMPT
PROMPT #######################################################################
break on role_name on owner
SELECT grantee "ROLE_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee IN (SELECT role FROM dba_roles) 
    AND grantee NOT IN ('DBA','SELECT_CATALOG_ROLE','EXECUTE_CATALOG_ROLE','DV_SECANALYST','DELETE_CATALOG_ROLE')
    AND owner IN ('SYS','SYSTEM')
    AND table_name IN ('USER$','USER_HISTORY$','SOURCE','LINK$','AUD$','FGA_LOG$','KU$_USER_VIEW'))
OR (grantee IN (SELECT role FROM dba_roles)
    AND grantee NOT IN ('DV_GOLDENGATE_ADMIN','DV_XSTREAM_ADMIN','DV_SECANALYST','DV_MONITOR',
                      'DV_ADMIN','DV_OWNER','DV_ACCTMGR','DV_PUBLIC','DV_PATCH_ADMIN','DV_STREAMS_ADMIN',
                      'DV_GOLDENGATE_REDO_ACCESS','DV_REALM_RESOURCE','DV_REALM_OWNER')
    AND owner ='DVSYS')
OR (grantee IN (SELECT role FROM dba_roles)
    AND grantee not in ('SELECT_CATALOG_ROLE','PUBLIC')
    AND owner='LBACSYS')
GROUP BY grantee, owner, grantor, table_name
ORDER BY grantee,owner,table_name;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT EXECUTE privileges on sensitive packages granted to roles
PROMPT
PROMPT #######################################################################
break on role_name on owner
SELECT grantee "ROLE_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee IN (SELECT role FROM dba_roles) 
    AND table_name IN ('UTL_SMTP','UTL_FILE','UTL_TCP','UTL_HTTP','DBMS_LOB','DBMS_SYS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE'))
GROUP BY (grantee, owner, grantor, table_name)
ORDER BY grantee, owner, table_name;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Users assigned to roles
PROMPT
PROMPT #######################################################################
col granted_role format a30
col grantee format a30
break on granted_role
SELECT granted_role, grantee, admin_option, default_role FROM dba_role_privs ORDER BY granted_role, grantee
/
clear breaks
PROMPT #######################################################################
PROMPT USERS USERS USERS USERS USERS USERS USERS
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT Top Role Owners
PROMPT
PROMPT #######################################################################
SELECT * FROM (SELECT grantee, count(granted_role) "NUMBER ROLES" 
FROM dba_role_privs 
WHERE grantee IN (SELECT username 
                  FROM dba_users 
                  WHERE username NOT IN ('SYS','SYSTEM')) 
GROUP BY grantee 
ORDER BY 2 desc) 
WHERE rownum<11
/
PROMPT #######################################################################
PROMPT
PROMPT Number of Roles granted to users
PROMPT
PROMPT #######################################################################
SELECT grantee, count(granted_role) "NUMBER ROLES" 
FROM dba_role_privs 
WHERE grantee IN (SELECT username 
                  FROM dba_users 
                  WHERE username NOT IN ('SYS','SYSTEM')) 
GROUP BY grantee 
ORDER BY grantee
/
PROMPT #######################################################################
PROMPT
PROMPT Roles granted to users
PROMPT
PROMPT #######################################################################
break on grantee
SELECT grantee, granted_role, admin_option, default_role 
FROM dba_role_privs
WHERE grantee NOT IN (SELECT role FROM dba_roles) AND grantee NOT IN ('SYS','PUBLIC')
ORDER BY grantee
/
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Users with SYSTEM as default tablespace
PROMPT
PROMPT #######################################################################
col property_name  format a30
col property_value format a30
col profile format a30
col external_name format a40
SELECT property_name, property_value
FROM database_properties where property_name in ('DEFAULT_PERMANENT_TABLESPACE','DEFAULT_TEMP_TABLESPACE');
prompt########
prompt 
SELECT account_status, username, default_tablespace, profile, external_name 
FROM dba_users 
WHERE default_tablespace='SYSTEM' 
ORDER BY account_status, username
/
PROMPT #######################################################################
PROMPT
PROMPT Users in this database
PROMPT
PROMPT #######################################################################
col password format a15
col profile format a30
SELECT account_status, username, created, lock_date, expiry_date, default_tablespace, profile, password, external_name 
FROM dba_users 
ORDER BY account_status, username
/
PROMPT #######################################################################
PROMPT
PROMPT Potential Root Kits - users not visible in DBA_USERS
PROMPT
PROMPT #######################################################################
col ext_username format a30 heading EXTERNAL_NAME
select u.name, 
       m.status,
       u.ext_username
       from sys.user$ u, 
            sys.user_astatus_map m
       where u.astatus = m.status#
       and u.type# = 1
MINUS
select username, 
       account_status, 
       external_name 
  from dba_users;
PROMPT #######################################################################
PROMPT
PROMPT Users whose passwords never expire
PROMPT
PROMPT #######################################################################
col profile format a25
col LIMIT format a10
col default_limit format a10
SELECT account_status, username, profile, limit, default_limit
FROM (
SELECT a.account_status, a.username, a.profile, b.limit, c.limit "DEFAULT_LIMIT"
FROM dba_users a JOIN dba_profiles b ON a.profile=b.profile LEFT OUTER JOIN dba_profiles c ON b.limit=c.profile
WHERE b.resource_name='PASSWORD_LIFE_TIME'
and (c.resource_name='PASSWORD_LIFE_TIME' OR c.resource_name IS NULL)
AND (b.limit='UNLIMITED' OR c.limit='UNLIMITED'))
ORDER BY account_status, username;
PROMPT #######################################################################
PROMPT
PROMPT Users not subject to failed login limits
PROMPT
PROMPT #######################################################################
SELECT account_status, username, profile, limit, default_limit
FROM (
SELECT a.account_status, a.username, a.profile, b.limit, c.limit "DEFAULT_LIMIT"
FROM dba_users a JOIN dba_profiles b ON a.profile=b.profile LEFT OUTER JOIN dba_profiles c ON b.limit=c.profile
WHERE b.resource_name='FAILED_LOGIN_ATTEMPTS'
and (c.resource_name='FAILED_LOGIN_ATTEMPTS' OR c.resource_name IS NULL)
AND (b.limit='UNLIMITED' OR c.limit='UNLIMITED'))
ORDER BY account_status, username;
PROMPT #######################################################################
PROMPT
PROMPT Roles granted to users
PROMPT
PROMPT #######################################################################
break on grantee
SELECT grantee, granted_role, admin_option, default_role 
FROM dba_role_privs 
WHERE grantee NOT IN ('SYS','SYSTEM')
ORDER BY grantee, granted_role;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Count of System level privileges granted to users
PROMPT
PROMPT #######################################################################
col USER format a30
select count(*) "COUNT_SYSPRIVS" , grantee "USER", account_status
  from dba_sys_privs, DBA_users
  where username = grantee
 group by grantee, account_status;
col grantee clear
PROMPT #######################################################################
PROMPT
PROMPT Object level Privileges on SYS, SYSTEM, OR DVSYS objects granted to users
PROMPT
PROMPT #######################################################################
COL select format a3 heading SEL
COL insert format a3 heading INS
COL update format a3 heading UPD
COL delete format a3 heading DEL
COL alter format a3 heading ALT
COL references format a3 heading REF
COL index format a3 heading IND
COL execute format a3 heading EXE
break on grantee
SELECT grantee "USER_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE (grantee NOT IN (SELECT role FROM dba_roles) 
    AND grantee NOT IN ('LBACSYS','DVSYS')
    AND owner IN ('SYS','SYSTEM')
    AND table_name IN ('USER$','USER_HISTORY$','SOURCE','LINK$','AUD$','FGA_LOG$','KU$_USER_VIEW'))
OR (grantee NOT IN (SELECT role FROM dba_roles)
    AND grantee NOT IN ('DV_GOLDENGATE_ADMIN','DV_XSTREAM_ADMIN','DV_SECANALYST','DV_MONITOR',
                      'DV_ADMIN','DV_OWNER','DV_ACCTMGR','DV_PUBLIC','DV_PATCH_ADMIN','DV_STREAMS_ADMIN',
                      'DV_GOLDENGATE_REDO_ACCESS','DV_REALM_RESOURCE','DV_REALM_OWNER')
    AND owner ='DVSYS')
OR (grantee NOT IN (SELECT role FROM dba_roles)
    AND grantee not in ('DVSYS','PUBLIC')
    AND owner='LBACSYS')
GROUP BY grantee, owner, grantor, table_name
ORDER BY grantee,owner,table_name;
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Object level Privileges on SYS *$ tables granted to users
PROMPT
PROMPT #######################################################################
col "Col1" format a25 wrap heading "Grantee"
col "Col2" format a25 wrap heading "Table_name"
SELECT DISTINCT GRANTEE "Col1", 'SYS.'||table_name "Col2"
 FROM DBA_TAB_PRIVS WHERE OWNER LIKE 'SYS' AND TABLE_NAME LIKE '%$';
col "Col1" clear
col "Col2" clear
PROMPT #######################################################################
PROMPT
PROMPT EXECUTE privileges on sensitive packages granted to users
PROMPT
PROMPT #######################################################################
break on role_name on owner
SELECT grantee "USER_NAME", owner, table_name, grantor,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE table_name IN ('UTL_SMTP','UTL_FILE','UTL_TCP','UTL_HTTP','DBMS_LOB','DBMS_SYS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE')
GROUP BY grantee, owner, grantor, table_name
ORDER BY grantee,owner,table_name;
clear breaks
PROMPT #######################################################################
PROMPT Sample Schemas in this database
PROMPT #######################################################################
SELECT username, account_status
FROM dba_users
WHERE username IN ('SCOTT','HR','OE','SH','PM');
PROMPT #######################################################################
PROMPT PUBLIC PUBLIC PUBLIC PUBLIC PUBLIC
PROMPT #######################################################################
PROMPT #######################################################################
PROMPT
PROMPT Roles Granted To Public
PROMPT
PROMPT #######################################################################
SELECT * FROM dba_role_privs WHERE grantee = 'PUBLIC' ORDER BY 1
/
PROMPT #######################################################################
PROMPT
PROMPT System Privileges Granted To Public
PROMPT
PROMPT #######################################################################
SELECT * FROM dba_sys_privs WHERE grantee = 'PUBLIC' ORDER BY privilege
/
PROMPT #######################################################################
PROMPT
PROMPT Object Privileges Granted To Public
PROMPT
PROMPT #######################################################################
col grantee format a30
col grantor format a30
break on owner on table_name
SELECT owner, table_name, grantor, grantee,
       max(decode(privilege,'SELECT','X')) "SELECT",
       max(decode(privilege,'INSERT','X')) "INSERT",
       max(decode(privilege,'UPDATE','X')) "UPDATE",
       max(decode(privilege,'DELETE','X')) "DELETE",
       max(decode(privilege,'ALTER','X')) "ALTER",
       max(decode(privilege,'REFERENCES','X')) "REFERENCES",
       max(decode(privilege,'INDEX','X')) "INDEX",
       max(decode(privilege,'EXECUTE','X')) "EXECUTE"
FROM dba_tab_privs
WHERE grantee ='PUBLIC'
and (owner <> 'SYS' AND table_name not LIKE 'java/%')
and (owner <> 'SYS' AND table_name not LIKE 'javax/%')
and (owner <> 'SYS' AND table_name not LIKE '/%')
group by owner, grantor, grantee, table_name
ORDER BY grantee,owner,table_name
/
clear breaks
PROMPT #######################################################################
PROMPT
PROMPT Column Privileges Granted To Public
PROMPT
PROMPT #######################################################################
SELECT substr(grantee,1,length(grantee)) ||':'|| 
substr(owner,1,length(owner)) ||':'|| 
substr(column_name,1,length(column_name)) ||':'|| 
substr(table_name,1,length(table_name)) ||':'|| substr(privilege,1,length(privilege))||':'
"grantee:owner:col:tab:priv"
FROM sys.dba_col_privs
WHERE grantee = 'PUBLIC'
ORDER BY table_name,column_name, privilege,grantee
/