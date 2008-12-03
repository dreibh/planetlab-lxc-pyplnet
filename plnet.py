# $Id$

import os
import socket
import time

import sioc
import modprobe

def InitInterfaces(logger, plc, data, root="", files_only=False):
    sysconfig = "%s/etc/sysconfig/network-scripts" % root

    # query running network interfaces
    devs = sioc.gifconf()
    ips = dict(zip(devs.values(), devs.keys()))
    macs = {}
    for dev in devs:
        macs[sioc.gifhwaddr(dev).lower()] = dev

    # assume data['networks'] contains this node's NodeNetworks
    interfaces = {}
    interface = 1
    hostname = data.get('hostname',socket.gethostname())
    networks = data['networks']
    failedToGetSettings = False
    for network in networks:
    	logger.verbose('net:InitInterfaces interface %d: %s'%(interface,network))
    	logger.verbose('net:InitInterfaces macs = %s' % macs)
        logger.verbose('net:InitInterfaces ips = %s' % ips)
        # Get interface name preferably from MAC address, falling back
        # on IP address.
        hwaddr=network['mac']
        if hwaddr <> None: hwaddr=hwaddr.lower()
        if hwaddr in macs:
            orig_ifname = macs[hwaddr]
        elif network['ip'] in ips:
            orig_ifname = ips[network['ip']]
        else:
            orig_ifname = None

	if orig_ifname:
       		logger.verbose('net:InitInterfaces orig_ifname = %s' % orig_ifname)
	
        inter = {}
        inter['ONBOOT']='yes'
        inter['USERCTL']='no'
        if network['mac']:
            inter['HWADDR'] = network['mac']

        if network['method'] == "static":
            inter['BOOTPROTO'] = "static"
            inter['IPADDR'] = network['ip']
            inter['NETMASK'] = network['netmask']

        elif network['method'] == "dhcp":
            inter['BOOTPROTO'] = "dhcp"
            if network['hostname']:
                inter['DHCP_HOSTNAME'] = network['hostname']
            else:
                inter['DHCP_HOSTNAME'] = hostname 
            if not network['is_primary']:
                inter['DHCLIENTARGS'] = "-R subnet-mask"

        if len(network['interface_tag_ids']) > 0:
            try:
                settings = plc.GetInterfaceTags({'interface_tag_id':
                                                 network['interface_tag_ids']})
            except:
                logger.log("net:InitInterfaces FATAL: failed call GetInterfaceTags({'interface_tag_id':{%s})"% \
                           network['interface_tag_ids'])
                failedToGetSettings = True
                continue # on to the next network

            for setting in settings:
                # to explicitly set interface name
                settingname = setting['name'].upper()
                if settingname in ('IFNAME','ALIAS','CFGOPTIONS','DRIVER'):
                    inter[settingname]=setting['value']
                else:
                    logger.log("net:InitInterfaces WARNING: ignored setting named %s"%setting['name'])

        # support aliases to interfaces either by name or HWADDR
        if 'ALIAS' in inter:
            if 'HWADDR' in inter:
                hwaddr = inter['HWADDR'].lower()
                del inter['HWADDR']
                if hwaddr in macs:
                    hwifname = macs[hwaddr]
                    if ('IFNAME' in inter) and inter['IFNAME'] <> hwifname:
                        logger.log("net:InitInterfaces WARNING: alias ifname (%s) and hwaddr ifname (%s) do not match"%\
                                       (inter['IFNAME'],hwifname))
                        inter['IFNAME'] = hwifname
                else:
                    logger.log('net:InitInterfaces WARNING: mac addr %s for alias not found' %(hwaddr,alias))

            if 'IFNAME' in inter:
                # stupid RH /etc/sysconfig/network-scripts/ifup-aliases:new_interface()
                # checks if the "$DEVNUM" only consists of '^[0-9A-Za-z_]*$'. Need to make
                # our aliases compliant.
                parts = inter['ALIAS'].split('_')
                isValid=True
                for part in parts:
                    isValid=isValid and part.isalnum()

                if isValid:
                    interfaces["%s:%s" % (inter['IFNAME'],inter['ALIAS'])] = inter 
                else:
                    logger.log("net:InitInterfaces WARNING: interface alias (%s) not a valid string for RH ifup-aliases"% inter['ALIAS'])
            else:
                logger.log("net:InitInterfaces WARNING: interface alias (%s) not matched to an interface"% inter['ALIAS'])
            interface -= 1
        else:
            if ('IFNAME' not in inter) and not orig_ifname:
                ifname="eth%d" % (interface-1)
                # should check if $ifname is an eth already defines
                if os.path.exists("%s/ifcfg-%s"%(sysconfig,ifname)):
                    logger.log("net:InitInterfaces WARNING: possibly blowing away %s configuration"%ifname)
            else:
		if ('IFNAME' not in inter) and orig_ifname:
                    ifname = orig_ifname
                else:
                    ifname = inter['IFNAME']
                interface -= 1
            interfaces[ifname] = inter
                
    m = modprobe.Modprobe()
    m.input("%s/etc/modprobe.conf" % root)
    for (dev, inter) in interfaces.iteritems():
        # get the driver string "moduleName option1=a option2=b"
        driver=inter.get('DRIVER','')
        if driver <> '':
            driver=driver.split()
            kernelmodule=driver[0]
            m.aliasset(dev,kernelmodule)
            options=" ".join(driver[1:])
            if options <> '':
                m.optionsset(dev,options)
    m.output("%s/etc/modprobe.conf" % root)

    # clean up after any ifcfg-$dev script that's no longer listed as
    # part of the NodeNetworks associated with this node

    # list all network-scripts
    files = os.listdir(sysconfig)

    # filter out the ifcfg-* files
    ifcfgs=[]
    for f in files:
        if f.find("ifcfg-") == 0:
            ifcfgs.append(f)

    # remove loopback (lo) from ifcfgs list
    lo = "ifcfg-lo"
    if lo in ifcfgs: ifcfgs.remove(lo)

    # remove known devices from icfgs list
    for (dev, inter) in interfaces.iteritems():
        ifcfg = 'ifcfg-'+dev
        if ifcfg in ifcfgs: ifcfgs.remove(ifcfg)

    # delete the remaining ifcfgs from 
    deletedSomething = False

    if not failedToGetSettings:
        for ifcfg in ifcfgs:
            dev = ifcfg[len('ifcfg-'):]
            path = "%s/ifcfg-%s" % (sysconfig,dev)
            logger.verbose("net:InitInterfaces removing %s %s"%(dev,path))
            os.system("/sbin/ifdown %s" % dev)
            deletedSomething=True
            os.unlink(path)

    # wait a bit for the one or more ifdowns to have taken effect
    if deletedSomething:
        time.sleep(2)

    # Process ifcg-$dev changes / additions
    newdevs = []
    for (dev, inter) in interfaces.iteritems():
        tmpnam = os.tmpnam()
        f = file(tmpnam, "w")
        f.write("# Autogenerated by NodeManager/net.py.... do not edit!\n")
        if 'DRIVER' in inter:
            f.write("# using %s driver for device %s\n" % (inter['DRIVER'],dev))
        f.write('DEVICE="%s"\n' % dev)
        
        # print the configuration values
        for (key, val) in inter.iteritems():
            if key not in ('IFNAME','ALIAS','CFGOPTIONS','DRIVER'):
                f.write('%s="%s"\n' % (key, val))

        # print the configuration specific option values (if any)
        if 'CFGOPTIONS' in inter:
            cfgoptions = inter['CFGOPTIONS']
            f.write('#CFGOPTIONS are %s\n' % cfgoptions)
            for cfgoption in cfgoptions.split():
                key,val = cfgoption.split('=')
                key=key.strip()
                key=key.upper()
                val=val.strip()
                f.write('%s="%s"\n' % (key,val))
        f.close()

        # compare whether two files are the same
        def comparefiles(a,b):
            try:
		logger.verbose("net:InitInterfaces comparing %s with %s" % (a,b))
                if not os.path.exists(a): return False
                fb = open(a)
                buf_a = fb.read()
                fb.close()

                if not os.path.exists(b): return False
                fb = open(b)
                buf_b = fb.read()
                fb.close()

                return buf_a == buf_b
            except IOError, e:
                return False

        path = "%s/ifcfg-%s" % (sysconfig,dev)
        if not os.path.exists(path):
            logger.verbose('net:InitInterfaces adding configuration for %s' % dev)
            # add ifcfg-$dev configuration file
            os.rename(tmpnam,path)
            os.chmod(path,0644)
            newdevs.append(dev)
            
        elif not comparefiles(tmpnam,path):
            logger.verbose('net:InitInterfaces Configuration change for %s' % dev)
            logger.verbose('net:InitInterfaces ifdown %s' % dev)
            # invoke ifdown for the old configuration
            os.system("/sbin/ifdown %s" % dev)
            # wait a few secs for ifdown to complete
            time.sleep(2)

            logger.log('replacing configuration for %s' % dev)
            # replace ifcfg-$dev configuration file
            os.rename(tmpnam,path)
            os.chmod(path,0644)
            newdevs.append(dev)
        else:
            # tmpnam & path are identical
            os.unlink(tmpnam)

    for dev in newdevs:
        cfgvariables = {}
        fb = file("%s/ifcfg-%s"%(sysconfig,dev),"r")
        for line in fb.readlines():
            parts = line.split()
            if parts[0][0]=="#":continue
            if parts[0].find('='):
                name,value = parts[0].split('=')
                # clean up name & value
                name = name.strip()
                value = value.strip()
                value = value.strip("'")
                value = value.strip('"')
                cfgvariables[name]=value
        fb.close()

        def getvar(name):
            if name in cfgvariables:
                value=cfgvariables[name]
                value = value.lower()
                return value
            return ''

        # skip over device configs with ONBOOT=no
        if getvar("ONBOOT") == 'no': continue

        # don't bring up slave devices, the network scripts will
        # handle those correctly
        if getvar("SLAVE") == 'yes': continue

        logger.verbose('net:InitInterfaces bringing up %s' % dev)
        os.system("/sbin/ifup %s" % dev)

