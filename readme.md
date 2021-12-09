[comment]: # "Auto-generated SOAR connector documentation"
# SecureSphere WAF

Publisher: AvantGarde Partners  
Connector Version: 1\.0\.2  
Product Vendor: Imperva  
Product Name: SecureSphere WAF  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 2\.0\.264  

This app implements <b>containment</b> actions by integrating with the <b>SecureServer</b> Device


"This app supports 'block ip' and 'unblock ip.' The asset definition includes both a Policy Name and
IP Group Name. When Block IP is called, a check is performed to see if the policy defined in the
Asset definition exists; if it does not exist it is created. The policy will block all IPs that
exist in the IP group specified in the Asset definition. IPs and/or networks sent to Block IP will
be added to the IP group specicied in the Asset definition. Unblock, will remove the IP/network from
the IP Group specified in the asset definition.  
  
Note: If you are on version \< 11.5.0.40 the policy will not be created automatically - instead
requiring that the policy be created manually. In all cases, the IP Group needs to be created
manually in SecureSphere prior to this App running successfully.",


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a SecureSphere WAF asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**mxAddress** |  required  | string | SecureSphere MX IP
**verifyCert** |  optional  | boolean | Verify Server Certificate
**mxPort** |  required  | string | SecureSphere MX Port \(default 8083\)
**mxUsername** |  required  | string | SecureSphere MX GUI Username
**mxPassword** |  required  | password | SecureSphere MX GUI Password
**policyName** |  required  | string | Custom Web Security Policy Name
**ipGroupName** |  required  | string | IP Group for Blocked IPs/Networks

### Supported Actions  
[block ip](#action-block-ip) - Block an IP address or network\.  
[unblock ip](#action-unblock-ip) - Unblock an IP address or network\.  
[test connectivity](#action-test-connectivity) - Validates connectivity to the Imperva SecureSphere Management Server  

## action: 'block ip'
Block an IP address or network\.

Type: **contain**  
Read only: **False**

To block a network provide network in IP field in CIDR notation xx\.xx\.xx\.xx/xx\. Otherwise, provide a single IP to block\. If the IP already exists within a blocked network the action will not fail, but a message indicating that it is already being blocked will be provided in the summary\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address/Network to Block\. | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.summary\.status\_string | string | 
action\_result\.summary\.status\_error | string | 
action\_result\.summary\.status\_code | string | 
action\_result\.status | string |   

## action: 'unblock ip'
Unblock an IP address or network\.

Type: **correct**  
Read only: **False**

To unblock a network provide network in IP field in CIDR notation xx\.xx\.xx\.xx/xx\. Otherwise, provide a single IP to unblock\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP Address/Network to Unblock | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.summary\.status\_string | string | 
action\_result\.summary\.status\_error | string | 
action\_result\.summary\.status\_code | string | 
action\_result\.status | string |   

## action: 'test connectivity'
Validates connectivity to the Imperva SecureSphere Management Server

Type: **test**  
Read only: **True**

Logs into the management server \(MX\), validating user credentials, api configuration, and address\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output