[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/vsantuka/vm2radius)
# VM2radius
By Vivek Santuka

This script monitors vCenter for power and IP events of a VM and generates
RADIUS requests to "authenticate" the VM with a RADIUS server like [Cisco ISE](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html).
If ISE is configured to assign SGTs, they can then be used in an upstream firewall
to filter based on SGTs. 

The authentication is simulated just like a MAB request and does not require a user account with password. Of course, the RADIUS server, Cisco ISE
in this case, would need to be configured to CONTINUE processing the request
even if the user is not found or authentication fails.

Samples from VMWare vSphere Python SDK are used in the code for most of the
communication with vSphere. The samples are distributed under the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).

Authentication requests are only generated for VMs with a known IP in vCenter.
IP address of a VM is only reported to vCenter if the VM has VMware-tools running.

The script will create a small text file to use as a Database (TinyDB). Make sure user 
has write privileges for this directory. The [dictionary](./dictionary) file is required to handle the RADIUS 
requests. Do not delete that file or its content.

The [stop.py](./stop.py) file can be used to generate Accounting STOP requests outside
of VM2RADIUS during testing. It will read the DB and send accounting STOP for all VMs
that have had an accounting start sent for them previously.

Lastly, VM2RADIUS requires pyrad, pyvmomi and Tinydb modules and is tested with Python 2.7
and vCenter 6.5 and 6.7.

Example use:

`python vm2radius.py -s vCenter.domain -u vcenter-use -p vcenter-pass -r ise.domain -k radius-secret`

Please refer to the [LICENSE](./LICENSE) file for terms of use.