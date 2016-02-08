#!/usr/bin/python
import argparse, datetime, os, time
import xml.etree.ElementTree as ET

# CLI arguments
parser = argparse.ArgumentParser(usage='%(prog)s foo.xml foo.csv', description='XML parser for the masses.')
parser.add_argument('input', help='input XML file (e.g. foo.xml)')
parser.add_argument('output', nargs='*', help='output CSV file (e.g. foo.csv)')
args = parser.parse_args()

tree = ET.parse(args.input)
root = tree.getroot()

try:
	os.remove(str(args.output).replace('[','').replace(']','').replace("'",''))
except OSError:
	pass

outputfile = open(str(args.output).replace('[','').replace(']','').replace("'",''), "a")

try:
	# Headers
	outputfile.write(str('"Nmap Scan Date","Nmap Arguments","StartTime","EndTime","Status","Address","Hostnmae","Port Protocol","Port Number","Port State","Port Service"\n'))

	# Parse through XML file
	for host in root.findall('host'):
		nmap_startstr = root.attrib.get('startstr')
		nmap_args = root.attrib.get('args')
		starttime = str(host.get('starttime'))
		endtime = str(host.get('endtime'))
		status = str(host.find('status').get('state'))
		address = str(host.find('address').get('addr'))

		try:
			hostname = 'None' if str(host.find('hostnames').find('hostname').get('name', {})) is None else str(host.find('hostnames').find('hostname').get('name', {}))
		except:
			hostname = 'None'

		for port in host.iter('port'):
			port_id = port.attrib.get('portid')
			port_protocol = port.attrib.get('protocol')
			port_state = port.find('state').attrib.get('state')
			port_service = port.find('service').attrib.get('name')

			# Write to file
			outputfile.write(str('"'+nmap_startstr+'","'+nmap_args+'","'+datetime.datetime.fromtimestamp(int(starttime)).strftime('%Y-%m-%d %H:%M:%S')+'","'+datetime.datetime.fromtimestamp(int(endtime)).strftime('%Y-%m-%d %H:%M:%S')+'","'+status+'","'+address+'","'+hostname+'","'+port_protocol+'","'+port_id+'","'+port_state+'","'+port_service+'"\n'))

except:
	raise