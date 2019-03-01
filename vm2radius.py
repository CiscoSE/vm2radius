#!/usr/bin/env python
#
#  VM2RADIUS
#  By Vivek Santuka
#
# This script uses the samples from VMWare vSphere Python SDK for most of the
# communication with vSphere. The samples are distributed under the Apache License
# found at http://www.apache.org/licenses/LICENSE-2.0
#
# This script monitors vCenter for power and IP events of a VM and generates
# RADIUS requests to "authenticate" the VM with ISE. If ISE is configured to assign SGTs
# they can then be used in an upstream firewall to filter based on SGTs.
#
# Requires ISE to be configured to CONTINUE processing even if authentication fails or
# user is not found. This is because this script uses VM names are username and a random
# password. These "usernames" won't exist in ISE.
#
# Free to copy, edit and use with proper credit
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl
import serviceutil
import argparse
import atexit
import collections
import getpass
import sys
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
import re
import random
import os
import ssl
from tinydb import TinyDB, Query
import socket

def get_args():
    """
    Supports the command-line arguments listed below.
    """

    parser = argparse.ArgumentParser(
        description='Arguments for VM2RADIUS',
        epilog="""
Example usage:
vm2radius.py -s vcenter -u root -p vmware -r ise -k secret
""")

    requiredNamed = parser.add_argument_group('required arguments')

    requiredNamed.add_argument('-s', '--host',
                        required=True, action='store',
                        help='Vcenter host to connect to')
    parser.add_argument('-o', '--port', type=int, default=443, action='store',
                        help='Port to connect on. Default is 443')
    requiredNamed.add_argument('-u', '--user', required=True, action='store',
                        help='Vcenter user name to use when connecting to it')
    parser.add_argument('-p', '--password', required=False, action='store',
                        help='Vcenter Password to use when connecting to it')
    requiredNamed.add_argument('-r', '--radius', required=True, action='store',
                        help='IP Address of the RADIUS Server')
    requiredNamed.add_argument('-k', '--secret', required=True, action='store',
                        help='RADIUS secret key to use')

    args = parser.parse_args()
    return args


def parse_propspec(propspec):
    """
    Parses property specifications.  Returns sequence of 2-tuples, each
    containing a managed object type and a list of properties applicable
    to that type

    :type propspec: collections.Sequence
    :rtype: collections.Sequence
    """

    props = []

    for objspec in propspec:
        if ':' not in objspec:
            raise Exception('property specification \'%s\' does not contain '
                            'property list' % objspec)

        objtype, objprops = objspec.split(':', 1)

        motype = getattr(vim, objtype, None)

        if motype is None:
            raise Exception('referenced type \'%s\' in property specification '
                            'does not exist,\nconsult the managed object type '
                            'reference in the vSphere API documentation' %
                            objtype)

        proplist = objprops.split(',')

        props.append((motype, proplist,))

    return props


def make_wait_options(max_wait_seconds=None, max_object_updates=None):
    waitopts = vmodl.query.PropertyCollector.WaitOptions()

    if max_object_updates is not None:
        waitopts.maxObjectUpdates = max_object_updates

    if max_wait_seconds is not None:
        waitopts.maxWaitSeconds = max_wait_seconds

    return waitopts


def make_property_collector(pc, from_node, props):
    """
    :type pc: pyVmomi.VmomiSupport.vmodl.query.PropertyCollector
    :type from_node: pyVmomi.VmomiSupport.ManagedObject
    :type props: collections.Sequence
    :rtype: pyVmomi.VmomiSupport.vmodl.query.PropertyCollector.Filter
    """

    # Make the filter spec
    filterSpec = vmodl.query.PropertyCollector.FilterSpec()

    # Make the object spec
    traversal = serviceutil.build_full_traversal()

    objSpec = vmodl.query.PropertyCollector.ObjectSpec(obj=from_node,
                                                       selectSet=traversal)
    objSpecs = [objSpec]

    filterSpec.objectSet = objSpecs

    # Add the property specs
    propSet = []
    for motype, proplist in props:
        propSpec = \
            vmodl.query.PropertyCollector.PropertySpec(type=motype, all=False)
        propSpec.pathSet.extend(proplist)
        propSet.append(propSpec)

    filterSpec.propSet = propSet

    try:
        pcFilter = pc.CreateFilter(filterSpec, True)
        atexit.register(pcFilter.Destroy)
        return pcFilter
    except vmodl.MethodFault, e:
        if e._wsdlName == 'InvalidProperty':
            print >> sys.stderr, "InvalidProperty fault while creating " \
                                 "PropertyCollector filter : %s" % e.name
        else:
            print >> sys.stderr, "Problem creating PropertyCollector " \
                                 "filter : %s" % str(e.faultMessage)
        raise


def monitor_property_changes(si, propspec, radius, seckey, myip, iterations=None):
    """
    :type si: pyVmomi.VmomiSupport.vim.ServiceInstance
    :type propspec: collections.Sequence
    :type iterations: int or None
    """

    pc = si.content.propertyCollector
    make_property_collector(pc, si.content.rootFolder, propspec)
    waitopts = make_wait_options(30)

    version = ''

    while True:
        if iterations is not None:
            if iterations <= 0:
                print ('Iteration limit reached, monitoring stopped')
                break

        result = pc.WaitForUpdatesEx(version, waitopts)

        # timeout, call again
        if result is None:
            continue

        # process results
        for filterSet in result.filterSet:
            for objectSet in filterSet.objectSet:
                moref = getattr(objectSet, 'obj', None)
                assert moref is not None, 'object moref should always be ' \
                                          'present in objectSet'

                moref = str(moref).strip('\'')

                kind = getattr(objectSet, 'kind', None)
                assert (
                    kind is not None and kind in ('enter', 'modify', 'leave',)
                ), 'objectSet kind must be valid'

#When the script starts, Vmware will return all VMs and kind will be set to enter.

                if kind == 'enter':
                    changeSet = getattr(objectSet, 'changeSet', None)
                    assert (changeSet is not None and isinstance(
                        changeSet, collections.Sequence
                    ) and len(changeSet) > 0), \
                        'enter or modify objectSet should have non-empty' \
                        ' changeSet'

                    changes = []
                    changes.append(('vmid', moref,))
                    srv = Client(server=radius, secret=seckey,
                                        dict=Dictionary("dictionary"))
                    for change in changeSet:
                        name = getattr(change, 'name', None)
                        assert (name is not None), \
                            'changeset should contain property name'
                        val = getattr(change, 'val', None)
                        if name == "name":
                            vname=str(val)
                            changes.append(('VM-Name', vname,))
                        elif name == "runtime.powerState":
                            vpower=str(val)
                            changes.append(('Power', vpower,))
                        elif name == "guest.net" and val != None:
                           for netinfo in val:
                                vnet=getattr(netinfo, "network", None)
                                vmac=getattr(netinfo, "macAddress", None)
		           changes.append(('network', str(vnet),))
                           changes.append(('macAddress', str(vmac),))
                        elif name == "runtime.host":
                            vhost=str(val).split(':')[-1].split("'")[0]
                            changes.append(('host', vhost,))
                        elif name =="guest.ipAddress" and val != None:
                            vipadd = str(val)
                            if "127.0.0.1" in vipadd:
                                vipadd = None
                            changes.append(("VM IP", vipadd,))
                        elif name =="guest.ipAddress" and val == None:
                            vipadd = None
                            changes.append(("VM IP", vipadd,))
                        else:
                           changes.append((name, str(val),))

#Send RADIUS Request for VMs that have IP
                    clss=""
                    sess=""
                    asid=""
                    if vipadd != None:
                        req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                                        User_Name=vname)
                        req["User-Password"] = req.PwCrypt("randompass")
                        req["Calling-Station-Id"] = vmac
                        req["Framed-IP-Address"] = vipadd
                        req["Service-Type"] = 2
                        req["NAS-Port-Type"] = 0
                        req["NAS-IP-Address"] = myip
                        if vhost!=None and vnet!=None:
                            req["Called-Station-Id"] = vhost+":"+vnet
                        try:
                            reply = srv.SendPacket(req)
                        except pyrad.client.Timeout:
                             sys.exit(1)
                        except socket.error as error:
                             sys.exit(1)
                        if reply.code == pyrad.packet.AccessAccept:
                            for i in reply.keys():
                                if i == "Class":
                                    clss = reply[i][0]
                                    m = re.search(":(.+?):", clss)
                                    if m:
                                        sess = m.group(1)

#Send Accounting Start packet matching the above request

                            req2 = srv.CreateAcctPacket(User_Name=vname)
                            req2["Calling-Station-Id"] = vmac
                            req2["Framed-IP-Address"] =  vipadd
                            req2["Service-Type"] = 2
                            req2["NAS-Port-Type"] = 0
                            req2["NAS-IP-Address"] = myip
                            req2["Acct-Status-Type"] = "Start"
                            req2["Class"] = clss
                            if vhost!=None and vnet!=None:
                                req2["Called-Station-Id"] = vhost+":"+vnet
                            asid = str(random.randint(1, 5000))
                            req2["Acct-Session-Id"] = asid
                            req2["Cisco-AVPair"] = "audit-session-id="+sess
                            req2["Acct-Delay-Time"] = 0
                            acct=srv.SendPacket(req2)
                        else:
                            print "Authentication Failed for VM - "+vname+" Configure ISE to CONTINUE on auth failure"

                    #Write to DB
                    db = TinyDB('1vm2radius.db')
                    db.insert({ 'vmid': moref,
                                'vname': vname,
                                'vipadd': vipadd,
                                'vhost': vhost,
                                'vnet': vnet,
                                'vpower': vpower,
                                'vmac': vmac,
                                'iclass': clss,
                                'isess': sess,
                                'asess': asid})
                    db.close()
                    #print "== %s ==" % moref
                    #print '\n'.join(['%s: %s' % (n, v,) for n, v in changes])
                    #print '\n'

#When there is a change in VM, the value of kind will be modify

	        elif kind == 'modify':
                    changeSet = getattr(objectSet, 'changeSet', None)
                    assert (changeSet is not None and isinstance(
                        changeSet, collections.Sequence
                    ) and len(changeSet) > 0), \
                        'enter or modify objectSet should have non-empty' \
                        ' changeSet'

                    #On receiving an update send an Accounting Stop first
                    #and clean the DB

                    srv = Client(server=radius, secret=seckey,
                                        dict=Dictionary("dictionary"))
                    db = TinyDB('1vm2radius.db')
                    detail = Query()
                    records = db.search(detail.vmid==moref)
                    for recs in records:
                        if recs['vipadd']!=None:
                            req2 = srv.CreateAcctPacket(User_Name=recs['vname'])
                            req2["Calling-Station-Id"] = str(recs['vmac'])
                            req2["Framed-IP-Address"] = str(recs['vipadd'])
                            req2["Service-Type"] = 2
                            req2["NAS-Port-Type"] = 0
                            req2["NAS-IP-Address"] = myip
                            req2["Acct-Status-Type"] = "Stop"
                            req2["Class"] = str(recs['iclass'])
                            req2["Acct-Session-Id"] = str(recs['asess'])
                            req2["Cisco-AVPair"] = "audit-session-id="+str(recs['isess'])
                            req2['Acct-Terminate-Cause'] = 2
                            req2['Acct-Delay-Time']=2
                            acct=srv.SendPacket(req2)
                        vname=recs['vname']
                    db.update({'vipadd': None}, detail.vmid == moref)
                    db.update({'iclass': ""}, detail.vmid == moref)
                    db.update({'asess': ""}, detail.vmid == moref)
                    db.update({'isess': ""}, detail.vmid == moref)
                    db.update({'vnet': ""}, detail.vmid == moref)
                    changes = []
                    for change in changeSet:
                        name = getattr(change, 'name', None)
                        assert (name is not None), \
                            'changeset should contain property name'
                        val = getattr(change, 'val', None)
                        if name=="runtime.powerState":
                                #Update in DB
                                db.update({'vpower': str(val)}, detail.vmid == moref)
                        elif name == "guest.net" and val != None:
                           for netinfo in val:
                                vnet=getattr(netinfo, "network", None)
                                vmac=getattr(netinfo, "macAddress", None)
                                db.update({'vnet': vnet}, detail.vmid == moref)
                                db.update({'vmac': vmac}, detail.vmid == moref)
                        elif name =="guest.ipAddress" and val != None:
                            vipadd = str(val)
                            if "127.0.0.1" in vipadd:
                                vipadd=None
                            db.update({'vipadd': vipadd}, detail.vmid == moref)
                        elif name =="guest.ipAddress" and val == None:
                            vipadd = None
                            db.update({'vipadd': vipadd}, detail.vmid == moref)
                        changes.append((name, val,))

                    if vipadd!=None:
                        req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                        User_Name=vname)
                        req["User-Password"] = req.PwCrypt("randompass")
                        req["Calling-Station-Id"] = vmac
                        req["Framed-IP-Address"] = vipadd
                        req["Service-Type"] = 2
                        req["NAS-Port-Type"] = 0
                        req["NAS-IP-Address"] = myip
                        if vhost!=None and vnet!=None:
                            req["Called-Station-Id"] = vhost+":"+vnet
                        try:
                            reply = srv.SendPacket(req)
                        except pyrad.client.Timeout:
                            sys.exit(1)
                        except socket.error as error:
                            sys.exit(1)
                        if reply.code == pyrad.packet.AccessAccept:
                            for i in reply.keys():
                                if i == "Class":
                                    clss = reply[i][0]
                                    m = re.search(":(.+?):", clss)
                                    if m:
                                        sess = m.group(1)

#Send Accounting Start packet matching the above request

                            req2 = srv.CreateAcctPacket(User_Name=vname)
                            req2["Calling-Station-Id"] = vmac
                            req2["Framed-IP-Address"] =  vipadd
                            req2["Service-Type"] = 2
                            req2["NAS-Port-Type"] = 0
                            req2["NAS-IP-Address"] = myip
                            req2["Acct-Status-Type"] = "Start"
                            req2["Class"] = clss
                            if vhost!=None and vnet!=None:
                                req2["Called-Station-Id"] = vhost+":"+vnet
                            asid = str(random.randint(1, 5000))
                            req2["Acct-Session-Id"] = asid
                            req2["Cisco-AVPair"] = "audit-session-id="+sess
                            acct=srv.SendPacket(req2)
                            db.update({'iclass': clss}, detail.vmid == moref)
                            db.update({'asess': asid}, detail.vmid == moref)
                            db.update({'isess': sess}, detail.vmid == moref)
                        else:
                            print "Authentication Failed for VM - "+vname+" Configure ISE to CONTINUE on auth failure"
                    db.close()
                    #print "== %s ==" % moref
                    #print '\n'.join(['%s: %s' % (n, v,) for n, v in changes])
                    #print '\n'
                #else:
                    #print "== %s ==" % moref
                    #print '(removed)\n'

        version = result.version

        if iterations is not None:
            iterations -= 1


def main():
    """
    Sample Python program for monitoring property changes to objects of
    one or more types to stdout
    """

    args = get_args()

    if args.password:
        password = args.password
    else:
        password = getpass.getpass(prompt='Enter password for host %s and '
                                   'user %s: ' % (args.host, args.user))

    msoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msoc.connect((args.radius, 1812 ))
    myip = msoc.getsockname()[0]

    #Clean up DB on start. Send accounting STOP for stale entries
    srv = Client(server=args.radius, secret=args.secret,
             dict=Dictionary("dictionary"))
    db = TinyDB('1vm2radius.db')
    dbq = Query()
    srec = db.search(dbq.iclass!="")
    for recs in srec:
        req2 = srv.CreateAcctPacket(User_Name=recs['vname'])
        req2["Calling-Station-Id"] = str(recs['vmac'])
        req2["Framed-IP-Address"] = str(recs['vipadd'])
        req2["Service-Type"] = 2
        req2["NAS-Port-Type"] = 0
        req2["NAS-IP-Address"] = myip
        req2["Acct-Status-Type"] = "Stop"
        req2["Class"] = str(recs['iclass'])
        req2["Acct-Session-Id"] = str(recs['asess'])
        req2["Cisco-AVPair"] = "audit-session-id="+str(recs['isess'])
        req2['Acct-Terminate-Cause'] = 2
        req2['Acct-Delay-Time']=2
        acct=srv.SendPacket(req2) 
    db.purge()
    db.close()

    try:
        #if args.disable_ssl_warnings:
        #    from requests.packages import urllib3
        #    urllib3.disable_warnings()
        if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)): 
           ssl._create_default_https_context = ssl._create_unverified_context

        si = SmartConnect(host=args.host, user=args.user, pwd=password,
                          port=int(args.port))

        if not si:
            print >>sys.stderr, "Could not connect to the specified host ' \
                                'using specified username and password"
            raise

        atexit.register(Disconnect, si)

        spec = ['VirtualMachine:name,runtime.powerState,runtime.host,guest.ipAddress,guest.net']
        propspec = parse_propspec(spec)

        ite = None
        print "Starting VM2RADIUS.   Press ^C to exit"
        monitor_property_changes(si, propspec, args.radius, args.secret, myip, ite)

    except vmodl.MethodFault, e:
        print >>sys.stderr, "Caught vmodl fault :\n%s" % str(e)
        raise
    except Exception, e:
        print >>sys.stderr, "Caught exception : " + str(e)
        raise


if __name__ == '__main__':
    try:
        main()
        sys.exit(0)
    except Exception, e:
        print >>sys.stderr, "Caught exception : " + str(e)
        raise
    except KeyboardInterrupt, e:
        print >>sys.stderr, "Exiting"
        sys.exit(0)


# vim: set ts=4 sw=4 expandtab filetype=python:
