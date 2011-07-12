#!/usr/bin/env python

import json
import re
import sys
import urllib2

# default kick options, override in /etc/puppet/enc.yaml
#
config = {
    'kick_uri':  'http://<bleep server>:<bleep port>',
    'kick_user': '<admin user>',
    'kick_pass': '<admin pass>'
}

# TODO(termie): why does a json file have a yaml extension?
with open('/etc/puppet/enc.yaml') as f:
    yaml_config = json.load(f)
    config.update(yaml_config)

# got the config... fetch kick info from os-kick.

hardware_uri = config['kick_uri'] + '/api/hardware/'

auth_handler = urllib2.HTTPBasicAuthHandler()
auth_handler.add_password(realm = 'kick dingus',
                          uri = config['kick_uri'],
                          user = config['kick_user'],
                          passwd = config['kick_pass'])

opener = urllib2.build_opener(auth_handler)
urllib2.install_opener(opener)

req = urllib2.Request(hardware_uri, None, {'Accept': 'application/json'})
r = urllib2.urlopen(req)

oskick_details = json.load(r)

# we should pull cluster name (and hence yaml file) from
# the oskick data, but we don't have multi-tenant support
# there yet, so we'll dummy it up

hostname = sys.argv[1] #.split('.')[0]

machine_info = [x for x in oskick_details if x['hostname'] == hostname ]
if not machine_info:
    print "Can't find machine info"
    sys.exit(1)

cluster_id = machine_info['cluster']['id']
cluster_name = machine_info['cluster']['short_name']


# TODO(termie): why does the json file have a yaml extension?
cluster_description = '/etc/puppet/%s.yaml' % cluster_name
with open(cluster_description) as fd:
    cluster_details = json.load(fd)


# walk through the cluster config, find all matches for
# each role.

roles_by_machine = {}
machines_by_role = {}

for role, rolematch in cluster_details['cluster'].items():
    for hwinfo in oskick_details:
        host = hwinfo['hostname']

        if host and re.match(rolematch, host):
            host_roles = roles_by_machine.get(host, set())
            host_roles.add(role)
            roles_by_machine[host] = host_roles

            role_hosts = machines_by_role.get(role, set())
            role_hosts.add(host)
            machines_by_role[role] = role_hosts

# Now generate the roles list
enc_manifest = { 'classes': [], 'parameters': {} }

#print "looking for roles for %s" % hostname

if hostname not in roles_by_machine:
    # not found..
    print "No roles!"
    sys.exit(1)

enc_manifest['classes'] = list(roles_by_machine[hostname])


for key, value in cluster_details['options'].items():
    new_value = value

    matchgroup = re.match("#\{(.*)\}", str(value))
    if matchgroup:
        # return the ip of the node (or first match)
        matching_host = [x['ip_address'] for x in oskick_details
                         if re.match(matchgroup.group(1), x['hostname'])]
        if matching_host:
            new_value = matching_host[0]

    matchgroup = re.match('@\{(.*)\}', str(value))
    if matchgroup:
        # return an array of matching ips
        pass

    enc_manifest['parameters'][key] = new_value

print json.dumps(enc_manifest, indent=2)
