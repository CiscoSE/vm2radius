# VM2radius

This script monitors vCenter for power and IP events of a VM and generates
RADIUS requests to "authenticate" the VM with a RADIUS server like Cisco ISE.
If ISE is configured to assign SGTs they can then be used in an upstream firewall
to filter based on SGTs. 

The authentication is simulated just like a MAB requestand does not require an
an user account with password. Ofcourse, the RADIUS server, Cisco ISE,
in this case would need to be confiugred to CONTINUE processing the request
even if the user is not found or authentication fails.

Samples from VMWare vSphere Python SDK are used in the code for most of the
communication with vSphere. The samples are distributed under the Apache License
found at http://www.apache.org/licenses/LICENSE-2.0

Authentication request are only generated for VMs with a known IP in vCenter.
IP address of a VM is only reported to vCenter if the VM has VMware-tools running.

The script will create a small text file to use as Database (TinyDB). Make sure user 
has write privilege in this directory. The dictionary file is required to the RADIUS 
requests. Do not delete that file or its content

The stop.py file can be used to generate Accounting STOP requests outside
of VM2RADIUS during testing. It will read the DB and send accounting STOP for all VMs
that have had an accounting start sent for previously.

Lastly, VM2RADIUS requires pyrad, pyvmomi and Tinydb modules and is tested with Python 2.7
and vCenter 6.5 and 6.7.

Free to copy, edit and use with proper credit

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
