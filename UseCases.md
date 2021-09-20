# Security Monitoring Use Cases

Table of Contents

1. [Splunk CIM Field Recommendations](#cim)
2. [Alerting and Normalization Methodology](#method)
2. [Use Case Overview and Testing](#usecases)

---

## Splunk CIM Field Recommendations <a name="cim"></a>

The section below describes some fundamentals for security monitoring using the Security Dashboards app and Splunk. 

### Splunk CIM Fields
- https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/CIMtoUBAfields
- https://docs.splunk.com/Documentation/CIM/4.19.0/User/CIMfields

### Recommended Security CIM Fields with Description


| field | description | example | internal |
|-------|-------------|-----------|--------|
| select | internal | n/a | yes |
| keyid | internal | n/a | yes |
| compareLatest | internal | n/a | yes |
| compareEarliest | internal | n/a | yes |
| indextime | The time event index | n/a | yes |
| eventtime | The time event occurred | n/a | no |
| alert\_level | The event alert level | low,medium,high | no |
| alert\_name | The event alert name | e.g. Many failed logins | no 
| customer | The customer name for event | n/a | no |
| source | The event source | e.g. WinEventLog:Powershell | no |
| action | The action taken | e.g. blocked, allowed, success, failure, unknown, added, delivered, blocked, quarantined, deleted, unknown | no |
| app | The application involved in the event | e.g. ssh, splunk, win:local | no |
| signature\_id | The event ID or code for the activity | e.g. 4624 | no |
| event\_id | The the unique identifier for the event | e.g. 12356789 | no |
| session\_id | The session ID of the event | e.g. 1234 | no |
| signature | The sub-category or signature of the event, if applicable. | e.g. EICAR | no |
| severity | The severity of the external alarm. | e.g. informational, unknown, low, medium, high, critical | no |
| result\_id | A result indicator for an action status. | e.g. 0x00001a, 404, lockout | no |
| change\_type | The type of change, such as filesystem or AAA (authentication, authorization, and accounting). | e.g. restart | no |
| duration | The amount of time it took for the action to complete in seconds | e.g. 10 | no |
| bytes | Total count of bytes handled by this device/interface | e.g. 1024 | no |
| bytes\_in | How many bytes this device/interface received. | e.g. 1024 | no |
| bytes\_out | How many bytes this device/interface sent. | e.g. 1024 | no | 
| description | The description of the event | e.g. An account was locked out | no |
| dvc | The device that reported the event. | e.g. host.lab.lan | no |
| src\_host | The source hostname of the network event | e.g. 1.1.1.1 | no |
| src\_nt\_domain | The source NT domain of the event | e.g. LAB | no |
| src\_user | The source user of the event | e.g. administrator | no |
| src\_ip | The source ip of the event | e.g. 2.2.2.2 | no |
| src\_port | The source port of the event | e.g. 22 | no |
| src\_mac | The source mac address of the event | e.g. 00:00:00:00:00:0A | no |
| dest\_host | The destination hostname of the network event | e.g. 1.1.1.1 | no |
| dest\_nt\_domain | The destination NT domain of the event | e.g. LAB | no |
| dest\_user | The destination user of the event | e.g. administrator | no |
| dest\_ip | The destination ip of the event | e.g. 2.2.2.2 | no |
| dest\_port | The destination port of the event | e.g. 22 | no |
| dest\_mac | The destination mac address of the event | e.g. 00:00:00:00:00:0B | no |process
| process | The process of the event, if applicable | e.g. c:\windows\system32\cmd.exe | no |
| process\_id | The id of the process of the event, if applicable | e.g. 11 | no |
| process\_name | The name of the process of the event, if applicable | e.g. cmd.exe | no |
| process\_hash | The hash of the process of the event, if applicable | e.g. c:\windows\system32\cmd.exe | no |
| parent\_process | The parent process of the event, if applicable | e.g. c:\windows\system32\cmd.exe | no |
| parent\_process\_id | The id of the parent process of the event, if applicable | e.g. 10 | no |
| parent\_process\_name | The name of the parent process of the event, if applicable | e.g. c:\windows\system32\cmd.exe | no |
| parent\_process\_hash | The hash of the parent process of the event, if applicable |  | no |
| object\_path | The path of the modified resource object, if applicable (such as a file, directory, or volume). | | no |
| object\_attrs | The attributes that were updated on the updated resource object, if applicable. | | no |
| registry\_path | The registry path of the event | e.g. HKLM\microsoft\windows\currentversion\run | no 
| registry\_value\_name | The registry value name of the event | e.g. Startup | no |
| registry\_value\_data | The registry value data of the event | e.g. c:\temp\malware.exe | no |
| service\_name | The name of the service of the event if applicable | e.g. PrintSpooler | no |
| transport | The transport use for the event | e.g. TCP | no |
| protocol | The protocol used for authentication | e.g. NTLM | no |
| url | The url of the event | e.g. http://www.cbc.ca | no |
| md5 | The md5 of the URL, file, process, malware event | | no |
| sha1 | The sha1 of the URL, file, process, malware event | | no |
| eventcount | The total number of events that occurred | e.g. 10 | no |
| mitre\_category | The MITRE ATT&CK category of the event | e.g. Persistence | no |
| mitre\_technique | The MITRE ATT&CK technique of the event | e.g. Security Support Provider | no |
| mitre\_technique\_id | The MITRE ATT&CK technique id of the event | e.g. T1101 | no |
| security\_alarms\_state\_key | internal | n/a | yes |
| state | internal | n/a | yes |
| closedtime | internal | n/a | yes |
| modifiedtime | internal | n/a | yes |
| createdtime | internal | n/a | yes |
| owner | internal | n/a | yes |
| security\_alarms\_annotation\_key | internal | n/a | yes |
| acknowledged | internal | n/a | yes |
| annotatedby | internal | n/a | yes |
| annotation | internal | n/a | yes |

---

## Alerting and Normalization Methodology <a name="method"></a>

### Example Format CIM Fields and Send to Index
```
| eval indextime = _indextime 
| eval raw = _raw 
| convert ctime(indextime) 
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
| fillnull value=""
| collect index=securityevents
```

### Example Query Format Filter by Event Type and Send to Index
```
index=windows source="wineventlog:security" signature_id=4625
``` Alert Details ```
| eval alert_name="UC01 - Many Failed Logins Per User"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Brute Force: Password Guessing"
| eval mitre_technique="Credential Access" 
| eval mitre_technique_id="T1110.001"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
| collect securityevents source=windowseventlog sourcetype=windowssecurityevents
```

### Example Query Format Filter by Event Count and Send to Index
```
index=windows source="wineventlog:security" signature_id=4625
``` Alert Details ```
| eval alert_name="UC01 - Many Failed Logins Per User"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Brute Force: Password Guessing"
| eval mitre_technique="Credential Access" 
| eval mitre_technique_id="T1110.001"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Count by Field  ```
| stats first(_time) AS _time,
first(indextime) AS indextime
first(eventtime) AS eventtime
first(alert_level) AS alert_level
first(alert_name) AS alert_name
first(customer) AS customer
first(source) AS source
list(action) AS action
list(app) AS app
list(signature_id) AS signature_id
list(event_id) AS event_id
list(session_id) AS session_id
list(signature) AS signature
list(severity) AS severity
list(result_id) AS result_id
list(change_type) AS change_type
list(duration) AS duration
list(bytes) AS bytes
list(bytes_in) AS bytes_in
list(bytes_out) AS bytes_out
list(description) AS description
list(dvc) AS dvc
list(src_host) AS src_host
list(src_nt_domain) AS src_nt_domain
``` list(src_user) AS src_user ```
list(src_ip) AS src_ip
list(src_port) AS src_port
list(src_mac) AS src_mac
list(dest_host) AS dest_host
list(dest_nt_domain) AS dest_nt_domain
list(dest_user) AS dest_user
list(dest_ip) AS dest_ip
list(dest_port) AS dest_port
list(dest_mac) AS dest_mac
list(process) AS process
list(process_id) AS process_id
list(process_name) AS process_name
list(process_hash) AS process_hash
list(parent_process) AS parent_process
list(parent_process_id) AS parent_process_id
list(parent_process_name) AS parent_process_name
list(parent_process_hash) AS parent_process_hash
list(object_path) AS object_path
list(object_attrs) AS object_attrs
list(registry_path) AS registry_path
list(registry_value_name) AS registry_value_name
list(registry_value_data) AS registry_value_data
list(service_name) AS service_name
list(transport) AS transport
list(protocol) AS protocol
list(url) AS url
list(md5) AS md5
list(sha1) AS sha1
first(mitre_category) AS mitre_category
first(mitre_technique) AS mitre_technique
first(mitre_technique_id) AS mitre_technique_id
list(raw) AS raw
count AS eventcount
by src_user
``` Filter by Min Event Count ```
| where eventcount > 5
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
| collect securityevents source=windowseventlog sourcetype=windowssecurityevents
```

### Example Lower Case All Field Names
```
|  foreach * [eval temp=lower("<<FIELD>>"), {temp}='<<FIELD>>'| fields - "<<FIELD>>" temp ]
```

---

## Use Case Overview and Testing <a name="usecases"></a>

### UC01 - Unusual amount of authentication failures

#### Timewindow
* greater than 5 in 30 mins

#### Search
```
``` Capture NTLM and Kerberos Failed Authentication (4625 can be included but may cause duplicates) ```
index=windows source="wineventlog:security" 
  (
  	(EventCode=4771 Failure_Code=0x18) 
  	OR (EventCode=4776 Error_Code=0xC000006A)
  	``` OR (EventCode=4625 Sub_Status=0xC000006A) ```
  )
``` Custom CIM Field Handling ```
| eval src_user=coalesce(src_user,user)
| eval src_ip=replace(src_ip,"\:\:ffff\:","")
| eval src_nt_domain=coalesce(src_nt_domain,coalesce(Supplied_Realm_Name,""))
``` Alert Details ```
| eval alert_name="UC01 - Many Failed Logins Per User"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Credential Access"
| eval mitre_technique="Brute Force: Password Guessing" 
| eval mitre_technique_id="T1110.001"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Count by Field  ```
| stats first(_time) AS _time,
first(indextime) AS indextime
first(eventtime) AS eventtime
first(alert_level) AS alert_level
first(alert_name) AS alert_name
first(customer) AS customer
first(source) AS source
list(action) AS action
list(app) AS app
list(signature_id) AS signature_id
list(event_id) AS event_id
list(session_id) AS session_id
list(signature) AS signature
list(severity) AS severity
list(result_id) AS result_id
list(change_type) AS change_type
list(duration) AS duration
list(bytes) AS bytes
list(bytes_in) AS bytes_in
list(bytes_out) AS bytes_out
list(description) AS description
list(dvc) AS dvc
list(src_host) AS src_host
```list(src_nt_domain) AS src_nt_domain```
```list(src_user) AS src_user```
list(src_ip) AS src_ip
list(src_port) AS src_port
list(src_mac) AS src_mac
list(dest_host) AS dest_host
list(dest_nt_domain) AS dest_nt_domain
list(dest_user) AS dest_user
list(dest_ip) AS dest_ip
list(dest_port) AS dest_port
list(dest_mac) AS dest_mac
list(process) AS process
list(process_id) AS process_id
list(process_name) AS process_name
list(process_hash) AS process_hash
list(parent_process) AS parent_process
list(parent_process_id) AS parent_process_id
list(parent_process_name) AS parent_process_name
list(parent_process_hash) AS parent_process_hash
list(object_path) AS object_path
list(object_attrs) AS object_attrs
list(registry_path) AS registry_path
list(registry_value_name) AS registry_value_name
list(registry_value_data) AS registry_value_data
list(service_name) AS service_name
list(transport) AS transport
list(protocol) AS protocol
list(url) AS url
list(md5) AS md5
list(sha1) AS sha1
first(mitre_category) AS mitre_category
first(mitre_technique) AS mitre_technique
first(mitre_technique_id) AS mitre_technique_id
list(raw) AS raw
count AS eventcount
by src_user, src_nt_domain
``` Filter by Min Event Count ```
| where eventcount > 5
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing

```
cmd > runas /user:domain\user notepad.exe
BADPASSWORD
```

#### Additional Testing Reference

* https://dspace.cvut.cz/bitstream/handle/10467/83217/F8-BP-2019-Kotlaba-Lukas-thesis.pdf?sequence=-1&isAllowed=y

### UC02 - Audit log cleared

#### Timewindow
* greater than 1 in 60 minutes

#### Search
```
``` Event Log Cleared ```
index=windows source="wineventlog:security"  EventCode=1102
``` Alert Details ```
| eval alert_name="UC02 - Event Log Cleared"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Defense Evasion"
| eval mitre_technique="Clear Windows Event Logs" 
| eval mitre_technique_id="T1070.001"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
powershell > Clear-EventLog –LogName Security
```

### UC03 - Netlogon service allowed insecure channel

#### Timewindow
* greater than 1 in 60 mins

#### Search 
```
``` ZeroLogon Indicator ```
index=windows source="wineventlog:system"  EventCode=5829
``` Alert Details ```
| eval alert_name="UC03 - Netlogon service allowed insecure channel"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Lateral Movement"
| eval mitre_technique="Exploitation of Remote Services" 
| eval mitre_technique_id="T1210"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
powershell > Test-ComputerSecureChannel
```

#### Additionall Testing Reference

* https://raw.githubusercontent.com/BC-SECURITY/Invoke-ZeroLogon/master/Invoke-ZeroLogon.ps1

### UC04 - Improperly signed image loaded into kernel

#### Timewindow
* greater than 1 in 60 mins

#### Search
```
``` Improper Code Signing ```
index=windows source="wineventlog:security"  EventCode=6281
``` Alert Details ```
| eval alert_name="UC04 - Improperly signed image loaded into kernel"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Defense Evasion"
| eval mitre_technique="Code Signing" 
| eval mitre_technique_id="T1553.002"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

### UC05 - Corrupt Image Loaded

#### Timewindow
* greater 1 in 60 mins

#### Search
```
``` Corrupt Image ```
index=windows source="wineventlog:security"  EventCode=5038
``` Alert Details ```
| eval alert_name="UC05 - Corrupt image loaded"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Defense Evasion"
| eval mitre_technique="Process Hollowing" 
| eval mitre_technique_id="T1055.012"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

### UC06 - User account locked out

#### Timewindow
* one or more in 5 minutes

#### Search

```
``` Account Lockout ```
index=windows source="wineventlog:security"  EventCode=4740
``` Custom CIM Field Handling ```
| eval dest_user=coalesce(dest_user,user)
``` Alert Details ```
| eval alert_name="UC06 - User account locked out"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Credential Access"
| eval mitre_technique="Brute Force" 
| eval mitre_technique_id="T1110"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
cmd > runas /user:domain\user notepad.exe
BADPASSWORD

cmd > runas /user:domain\user notepad.exe
BADPASSWORD

cmd > runas /user:domain\user notepad.exe
BADPASSWORD

cmd > runas /user:domain\user notepad.exe
BADPASSWORD

...Repeat Until Lockout Limit...
```

### UC07 - Explicit creds used for logon

#### Timewindow
* one or more in 5 minutes

#### Search
```
``` Explicit Creds ```
index=windows source="wineventlog:security"  EventCode=4648
``` Custom CIM Field Handling ```
| eval dest_user=coalesce(dest_user,user)
``` Alert Details ```
| eval alert_name="UC07 - Explicit creds used for logon"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Credential Access"
| eval mitre_technique="Brute Force" 
| eval mitre_technique_id="T1110"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```
#### Testing
```
cmd > runas /user:domain\user notepad.exe
PASSWORD
```

### UC08 - Multiple password changes for different users from the same source

#### Timewindow
* one or more event with greater than one distinct user in 60 minutes

#### Search

```
``` Multiple Password Resets ```
index=windows source="wineventlog:security"  EventCode=4724
``` Custom CIM Field Handling ```
| eval dest_user=coalesce(dest_user,user)
``` Alert Details ```
| eval alert_name="UC08 - Multiple password changes for different users from the same source"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Persistence"
| eval mitre_technique="Account Manipulation" 
| eval mitre_technique_id="T1098"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Count by Field  ```
| stats first(_time) AS _time,
first(indextime) AS indextime
first(eventtime) AS eventtime
first(alert_level) AS alert_level
first(alert_name) AS alert_name
first(customer) AS customer
first(source) AS source
list(action) AS action
list(app) AS app
list(signature_id) AS signature_id
list(event_id) AS event_id
list(session_id) AS session_id
list(signature) AS signature
list(severity) AS severity
list(result_id) AS result_id
list(change_type) AS change_type
list(duration) AS duration
list(bytes) AS bytes
list(bytes_in) AS bytes_in
list(bytes_out) AS bytes_out
list(description) AS description
list(dvc) AS dvc
list(src_host) AS src_host
```list(src_nt_domain) AS src_nt_domain```
```list(src_user) AS src_user```
list(src_ip) AS src_ip
list(src_port) AS src_port
list(src_mac) AS src_mac
list(dest_host) AS dest_host
list(dest_nt_domain) AS dest_nt_domain
list(dest_user) AS dest_user
list(dest_ip) AS dest_ip
list(dest_port) AS dest_port
list(dest_mac) AS dest_mac
list(process) AS process
list(process_id) AS process_id
list(process_name) AS process_name
list(process_hash) AS process_hash
list(parent_process) AS parent_process
list(parent_process_id) AS parent_process_id
list(parent_process_name) AS parent_process_name
list(parent_process_hash) AS parent_process_hash
list(object_path) AS object_path
list(object_attrs) AS object_attrs
list(registry_path) AS registry_path
list(registry_value_name) AS registry_value_name
list(registry_value_data) AS registry_value_data
list(service_name) AS service_name
list(transport) AS transport
list(protocol) AS protocol
list(url) AS url
list(md5) AS md5
list(sha1) AS sha1
first(mitre_category) AS mitre_category
first(mitre_technique) AS mitre_technique
first(mitre_technique_id) AS mitre_technique_id
list(raw) AS raw
count AS eventcount
dc(dest_user) AS distinct_users
by src_user, src_nt_domain
``` Filter by Min Event Count ```
| where eventcount >= 1 AND distinct_users > 1
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
powershell > 
$user = 'User1'
$newPass = 'PASSWORD_HERE'
Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$newPass" -Force)

powershell >
$user = 'User2'
$newPass = 'PASSWORD_HERE'
Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$newPass" -Force)
```

### UC09 - Firewall incoming application traffic blocked

#### Timewindow
* one or more in 5 minute window

#### Search
```
``` Firewall Blocked Application Listener ```
index=windows source="wineventlog:security"  EventCode=5031
``` Custom CIM Field Handling ```
| eval process=coalesce(process,Application)
``` Alert Details ```
| eval alert_name="UC09 - Firewall incoming application traffic blocked"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Command and Control"
| eval mitre_technique="Application Layer Protocol" 
| eval mitre_technique_id="T1071"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing

```
powershell > 
Function Receive-TCPMessage {
    Param ( 
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()] 
        [int] $Port
    ) 
    Process {
        Try { 
            # Set up endpoint and start listening
            $endpoint = new-object System.Net.IPEndPoint([ipaddress]::any,$port) 
            $listener = new-object System.Net.Sockets.TcpListener $EndPoint
            $listener.start() 
 
            # Wait for an incoming connection 
            $data = $listener.AcceptTcpClient() 
        
            # Stream setup
            $stream = $data.GetStream() 
            $bytes = New-Object System.Byte[] 1024

            # Read data from stream and write it to host
            while (($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
                $EncodedText = New-Object System.Text.ASCIIEncoding
                $data = $EncodedText.GetString($bytes,0, $i)
                Write-Output $data
            }
         
            # Close TCP connection and stop listening
            $stream.close()
            $listener.stop()
        }
        Catch {
            "Receive Message failed with: `n" + $Error[0]
        }
    }
}

$msg = Receive-TCPMessage -Port 29800
```

### UC10 - Windows Security-Group Policy settings for Windows Firewall has changed

> Event 4954 is very prone to false positive and the event has no change context. 

#### Timewindow
* one or more in 5 minutes

#### Search
```
``` Firewall Policy Changed ```
index=windows source="wineventlog:security"  EventCode=4954
``` Custom CIM Field Handling ```
| eval process=coalesce(process,Application)
``` Alert Details ```
| eval alert_name="UC10 - Group Policy settings for Windows Firewall has changed"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Command and Control"
| eval mitre_technique="Application Layer Protocol" 
| eval mitre_technique_id="T1071"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

### UC11 - Password Hash for an account accessed

#### Timewindow
* one or more in 5 minutes

#### Search
```
``` Password Hash Access ```
index=windows source="wineventlog:security"  EventCode=4782
``` Alert Details ```
| eval alert_name="UC11 - Password Hash for an account accessed"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Credential Access"
| eval mitre_technique="OS Credential Dumping" 
| eval mitre_technique_id="T1003"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Additional Testing Reference

* https://aws.amazon.com/blogs/security/how-to-migrate-your-on-premises-domain-to-aws-managed-microsoft-ad-using-admt/
* https://malwarenailed.blogspot.com/2018/08/hunting-for-malicious-dcsync-operations.html (optional 4662)


### UC12 - A rule was added to windows firewall exception list

> Note: Event Code 4946 replaced with Windows Firewall Event Code 2004 to provide more context

#### Timewindow
* one or more in 5 minutes

#### Search
```
``` Firewall Modification ```
index=windows source="wineventlog:security"  EventCode=4946
``` Alert Details ```
| eval alert_name="UC12 - A rule was added to windows firewall exception list"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Command and Control"
| eval mitre_technique="Application Layer Protocol" 
| eval mitre_technique_id="T1071"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
powershell> New-NetFirewallRule -DisplayName "Allow TCP 12345" -Direction Inbound -Action Allow -EdgeTraversalPolicy Allow -Protocol TCP -LocalPort 12345"
```
### UC13 - A rule was modified to windows firewall exception list

> Note: Event Code 4947 replaced with Windows Firewall Event Code 2005 for more context

#### Search 
```
``` Firewall Modification ```
index=windows source="wineventlog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"  EventCode=2005
``` Custom CIM Field Handling ```
| eval parent_process=coalesce(parent_process,Modifying_Application)
| eval process=coalesce(process,Application)
| eval protocol=coalesce(protocol,Protocol)
``` Alert Details ```
| eval alert_name="UC12 - A rule was added to windows firewall exception list"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Command and Control"
| eval mitre_technique="Application Layer Protocol" 
| eval mitre_technique_id="T1071"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
powershell > Set-NetFirewallRule -DisplayName "Allow TCP 12345" -RemoteAddress "192.168.0.2"
```

### UC14 - A setting was changed in windows firewall

#### Timewindow
* one or more in 5 minute window

#### Search
```
``` Firewall Setting Change ```
index=windows source="wineventlog:security"  EventCode=4950
``` Alert Details ```
| eval alert_name="UC13 - A setting was changed in windows firewall"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Defense Evasion"
| eval mitre_technique="Impair Defenses" 
| eval mitre_technique_id="T1562"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
powershell > Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

### UC15 - Windows registry modified

#### Timewindow
* one or more in 5 minute window

#### Search
```
``` Windows Registry Modification ```
index=windows source="wineventlog:security"  EventCode=4657
``` Alert Details ```
| eval alert_name="UC14 - Windows registry modified"
| eval alert_level="RED"
| eval customer="canadaguaranty"
``` MITRE Details (if applicable) ```
| eval mitre_category="Defense Evasion"
| eval mitre_technique="Impair Defenses" 
| eval mitre_technique_id="T1562"
``` Capture RAW and INDEXTIME  ```
| eval indextime = _indextime 
| eval raw = _raw 
| eval eventtime=_time
| convert ctime(indextime) 
| convert ctime(eventtime)
``` Return CIM Fields Only  ```
| fields  _time, indextime, eventtime, alert_level, alert_name, customer, action, app, source, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
``` Fill NULL Fields With Empty String And Lower Case All Values  ```
| fillnull value=""
| foreach * 
    [ 
    eval <<FIELD>>=if('<<FIELD>>'!=raw,lower(<<FIELD>>),<<FIELD>>)
    ]
``` Table Format Results  ```
| table _time, indextime, alert_level, alert_name, customer, source, action, app, signature_id, event_id, session_id, signature, severity, result_id, change_type, duration, bytes, bytes_in, bytes_out, description, dvc, src_host, src_nt_domain, src_user, src_ip, src_port, src_mac, dest_host, dest_nt_domain, dest_user, dest_ip, dest_port, dest_mac, process, process_id, process_name, process_hash, parent_process, parent_process_id, parent_process_name, parent_process_hash, object_path, object_attrs, registry_path, registry_value_name, registry_value_data, service_name, transport, protocol, url, md5, sha1, eventcount, mitre_category, mitre_technique, mitre_technique_id, raw
|  collect index=securityevents source=windowseventlog:alert sourcetype=windowseventlog:alert
```

#### Testing
```
powershell > $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

$Name = "Test"

$value = "C:\Windows\System32\calc.exe"

New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
```

#### Additional Testing Reference

* https://support.microsoft.com/en-us/topic/40ed412e-5a42-9f7d-d6b4-a1726a205919