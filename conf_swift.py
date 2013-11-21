#!/usr/bin/env python
#author: Cristina Filgueira
#version: 0.01   
####### Date ########################## Changes #####################################
#	worker
#-----------------------------------------------------------------------
#	25-10-2013			Added: change_ip_proxy_config_file,
#	ct					add_user, run_swift_proxy_services,
#						run_swift_storage_services
#						build_ring,  change_config_files_storage_nodes,
#						change_pipeline_to_use_keystone,
#						configure_storage_nodes,configure_proxy_node,
#						setup_volume_node,
#	06-11-2013			Added: create_directories, enable_rsync
#	joaquin				Modified: change_config_files_storage_nodes
#	
#	15-11-2013			Added:
#	ct					Modified: enable_rsync,
#						change_config_files_storage_nodes,
#						add_user, 
#	18-11-2013			Modified: change_config_files_storage_nodes (pipeline step missed).
#	ct					add_user, change_proxy_file, create_certificates,
#						change_proxy_auth_to_use_keystone,build_ring
#	20-11-2013			Deleted: setup_volume_node		
#	ct
#
#	21-11-2013			Modified: get_data_from_gui, change_config_files_storage_nodes
#	joaquin
#####################################################################################

#I assume we have config-files.conf

import os,json
from fabric.api import local

CONFIG_FILE = "/home/ct/gui_data.cfg"
SWIFT_PATH = "/etc/swift/"
PORT="8076"
DEBUG=True


def get_data_from_gui(key): 
	with open(CONFIG_FILE, 'rb') as fp:
		json_data = json.load(fp)

		#Returns the value for a specified key from the python dictionary
		if key in json_data:
			return json_data.get(key)
		else:	 
			if DEBUG: 
				print "Key not in dictionary"
		sys.exit()

#############################  PROXY NODE  #################################
#                                                                          #
############################################################################



def change_proxy_config_file():
	# Copy the file from the source if it doesn't exit.
	# /etc/swift/proxy-server.conf
	# Group must be '.admin' '.reseller_admin' or ''.
	ip_proxy = os.popen("ifconfig -a | awk '/(cast)/ { print $2 }' | cut -d':' -f2 | head -1")
	ip_proxy = ip_proxy.read().rstrip('\n')
	proxy_port = PORT
	local("sed -i 's/# bind_ip = 0.0.0.0/bind_ip = "+ip_proxy+"/' "+SWIFT_PATH+"proxy-server.conf")
	local("sed -i 's/# bind_port = 80/bind_port = "+proxy_port+"/' "+SWIFT_PATH+"proxy-server.conf")
	local("sed -i '37s/proxy-logging //g' "+SWIFT_PATH+"proxy-server.conf")
	local("sed -i '37s/slo ratelimit //g' "+SWIFT_PATH+"proxy-server.conf")
	local("sed -i '37s/container-quotas account-quotas //g' "+SWIFT_PATH+"proxy-server.conf")
	local("sed -i 's/# key_file/key_file/' "+SWIFT_PATH+"proxy-server.conf")
	local("sed -i 's/# cert_file/cert_file/' "+SWIFT_PATH+"proxy-server.conf")
	local("sed -i '/user/d' "+SWIFT_PATH+"proxy-server.conf")
	add_user()
	#local("sed -i 's/# memcache_servers = 127.0.0.1/memcache_servers = "+PROXY_IP+"/' "+SWIFT_PATH+"proxy-server.conf")


#Create a user for tempauth authentication, after add a user you may to
#start proxy services run_swift_proxy_services(). 
def add_user():
	username = get_data_from_gui("username")
	password = get_data_from_gui("password")
	account = get_data_from_gui("account")
	group = get_data_from_gui("role")
	user = "user_%s_%s = %s \.%s "%(account,username,password,group)
	local ("sed -i '/use\ =\ egg:swift#tempauth/s/$/\\n"+user+"/' "+SWIFT_PATH+"proxy-server.conf")


def run_swift_proxy_services():
	try:
		os.system(os.P_NOWAIT ,"swift-init proxy restart")
	except:
		pass


def run_swift_storage_services():
	try:
		local ("swift-init object container account restart")
	except:
		pass


def build_ring():
	part_power = '18'
	min_part_hours = '1'
	number_of_replicas = get_data_from_gui("copies")
	number_of_zones  = get_data_from_gui("zones")
	nodes = get_data_from_gui("storage")
	if number_of_replicas > len(nodes) or number_of_replicas > number_of_zones:
		number_of_replicas = len(nodes)
		number_of_zones = len(nodes)
	elif number_of_zones > len(nodes):
		number_of_zones = len(nodes)
	
	#Create builder files for ring.
	local("cd /etc/swift")
	local("swift-ring-builder account.builder create %s %s %s" % (part_power,number_of_replicas,min_part_hours))
	local("swift-ring-builder container.builder create %s %s %s" % (part_power,number_of_replicas,min_part_hours))
	local("swift-ring-builder object.builder create %s %s %s" % (part_power,number_of_replicas,min_part_hours))

	#Building rings one node per zone.
	for i in range(len(nodes)):
		local ("swift-ring-builder account.builder add z%s-%s:6002/%s 100"%(nodes[i]["zone"],nodes[i]["ip"],nodes[i]["device"]))
		local ("swift-ring-builder container.builder add z%s-%s:6001/%s 100"%(nodes[i]["zone"],nodes[i]["ip"],nodes[i]["device"]))
		local ("swift-ring-builder object.builder add z%s-%s:6000/%s 100"%(nodes[i]["zone"],nodes[i]["ip"],nodes[i]["device"]))
	
	local("swift-ring-builder object.builder rebalance")
	local("swift-ring-builder container.builder rebalance")
	local("swift-ring-builder account.builder rebalance")
	local("chown -R swift:swift /etc/swift")
	local("chown -R swift:swift /var/cache/swift")
	run_swift_proxy_services()
	
def create_swift_conf():
	local("cat >/etc/swift/swift.conf <<EOF\n\
[swift-hash]\n\
# random unique strings that can never change (DO NOT LOSE)\n\
swift_hash_path_prefix = `od -t x8 -N 8 -A n </dev/random`\n\
swift_hash_path_suffix = `od -t x8 -N 8 -A n </dev/random`\n\
EOF\n")


def configure_proxy_node():
	#TO_DO: copy this file in every node.
	create_swift_conf()
	general_node_configuration()
	create_ssl_certificates()
	change_ip_memcache()	
	change_proxy_config_file()
	#The ring will be built in the same node than proxy.
	build_ring()


def create_ssl_certificates():
	country = "IE"
	state = "Cork"
	company = "MPSTOR"
	city = "Cork"
	domain = "mpstor.com"
	org = "MPSTOR"
	email = "support@mpstor.com"
	subj = "/C=%(country)s/ST=%(state)s/O=%(company)s/localityName=%(city)s/commonName=%(domain)s/organizationalUnitName=%(org)s/emailAddress=%(email)s" \
		% {
			"country": country,
			"state": state,
			"company": company,
			"city": city,
			"domain": domain,
			"org": org,
			"email": email,
		}
	os.chdir("/etc/swift")
	local('openssl req -new -x509 -subj "%s" -nodes -out proxy.crt -keyout proxy.key' % subj)


def change_ip_memcache():
	#TODO: If the configure file doesn't exit, copy it from the source.
	ip_proxy = os.popen("ifconfig -a | awk '/(cast)/ { print $2 }' | cut -d':' -f2 | head -1")
	ip_proxy = ip_proxy.read().rstrip('\n')
	local("sed -i 's/# memcache_servers = 127.0.0.1:11211/memcache_servers = "+ip_proxy+"/' "+SWIFT_PATH+"memcache.conf")
	os.system("/usr/bin/memcached -u swift start &")


#############################  STORAGE NODE ################################
#                                                                          #
############################################################################


def configure_storage_nodes():
	general_node_configuration()
	change_config_files_storage_nodes()
	run_swift_storage_services()


#These folders should be in every node, proxy included.
def general_node_configuration():
	try:
		local("adduser -S swift")
		local("mkdir -p /etc/swift /var/run/swift /var/cache/swift")
		#We need to add to /etc/rc.local entries for /var/run/swift to avoid lost when system shuts down
		local("chown -R swift:swift /etc/swift/ /var/run/swift/ /var/cache/swift/")
	except:
		pass


def change_config_files_storage_nodes():
	ip = os.popen("ifconfig -a | awk '/(cast)/ { print $2 }' | cut -d':' -f2 | head -1")
	ip = ip.read().rstrip('\n')
	local("mkdir -p /srv/node/ ")
	local("chown -R swift:swift /srv/node/")

	# account-server.conf
	local("sed -i 's/#[\ ]*bind_ip[\ ]*=[\ ]*[0-9 .]*/bind_ip="+ip+"/' "+SWIFT_PATH+"account-server.conf")
	local("sed -i 's/#[\ ]*workers[\ ]*=[\ ]*[0-9 .]*/workers=2/' "+SWIFT_PATH+"account-server.conf")
	local("sed -i 's/pipeline[\ ]*=[\ ]*healthcheck[\ ]*recon[\ ]*account-server/pipeline=account-server/' "+SWIFT_PATH+"account-server.conf")
	# container-server.conf
	local("sed -i 's/#[\ ]*bind_ip[\ ]*=[\ ]*[0-9 .]*/bind_ip="+ip+"/' "+SWIFT_PATH+"container-server.conf")
	local("sed -i 's/#[\ ]*workers[\ ]*=[\ ]*[0-9 .]*/workers=2/' "+SWIFT_PATH+"container-server.conf")
	local("sed -i 's/pipeline[\ ]*=[\ ]*healthcheck[\ ]*recon[\ ]*container-server/pipeline=container-server/' "+SWIFT_PATH+"container-server.conf")
	# object-server.conf
	local("sed -i 's/#[\ ]*bind_ip[\ ]*=[\ ]*[0-9 .]*/bind_ip="+ip+"/' "+SWIFT_PATH+"object-server.conf")
	local("sed -i 's/#[\ ]*workers[\ ]*=[\ ]*[0-9 .]*/workers=2/' "+SWIFT_PATH+"object-server.conf")
	local("sed -i 's/pipeline[\ ]*=[\ ]*healthcheck[\ ]*recon[\ ]*object-server/pipeline=object-server/' "+SWIFT_PATH+"object-server.conf")
	# rsyncd.conf
	local ("sed -i '1i address\ =\ "+ip+"' '/etc/rsyncd.conf'")
	path = get_path(ip)
	print path
	local("sed -i 's|[\ ]*path[\ ]*=[\ ]*|path="+path+"|' '/etc/rsyncd.conf'")
	enable_rsync()

	try:
		local("rsync --daemon /etc/rsyncd.conf")
	except:
		if DEBUG:
			print "Error trying to rsync."
		pass

def get_path(ip):
	array = get_data_from_gui("storage")
	for index in range(len(array)):
		if array[index].get('ip')==ip:
			return array[index].get('path')

# Edit RSYNC_ENABLE to true in rsync file.
def enable_rsync():
	try:
		local("sed -i 's/RSYNC_ENABLE=false/RSYNC_ENABLE=true/' /etc/default/rsync")
	except:
		local("cat > /etc/default/rsync <<EOF\nRSYNC_ENABLE=true\nEOF")
		if DEBUG:
			print "Creating /etc/default/rsync"
		pass


def configure_swift():
	is_proxy = str2bool(get_data_from_gui("proxy"))
	if is_proxy :
		configure_proxy_node()
	else:
		print "Hola"
		configure_storage_nodes()
configure_storage_nodes()
