
"This app supports 'block ip' and 'unblock ip.' The asset definition includes both a Policy Name and
IP Group Name. When Block IP is called, a check is performed to see if the policy defined in the
Asset definition exists; if it does not exist it is created. The policy will block all IPs that
exist in the IP group specified in the Asset definition. IPs and/or networks sent to Block IP will
be added to the IP group specicied in the Asset definition. Unblock, will remove the IP/network from
the IP Group specified in the asset definition.  
  
Note: If you are on version \< 11.5.0.40 the policy will not be created automatically - instead
requiring that the policy be created manually. In all cases, the IP Group needs to be created
manually in SecureSphere prior to this App running successfully.",
