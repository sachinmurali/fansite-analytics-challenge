import os
import sys
from datetime import datetime
from collections import defaultdict

# Function to identify the top 10 active addresses
# Using a hash map, the count of the number of times a given IP occurs in the input file is maintained
# The hash map is then sorted and the top ten counts are returned
def top_active_addresses(logs, hosts_file):
	address_count = dict()

	for log in logs:
		if not log[0] in address_count:
			address_count[log[0]] = 1
		else:
			address_count[log[0]] += 1
	top_10 = sorted(address_count.iteritems(), key=lambda x:(-x[1], x[0]))[:10]

	with open(hosts_file, 'wb') as hosts:
		for x in top_10:
			hosts.write("{0},{1}\n".format(*x))

# Function to identify the top 10 resources that consumed the most bandwidth
# Using hash map, the amount of bandwidth used by a resource is maintained
# The top ten resources are returned after sorting the hash map
def bw_intensive_resources(logs, resources_file):
	resources = dict()

	for log in logs:
		byte_count = log[4]
		resource = log[2].split()

		if len(resource) < 3:
			continue

		if not resource[1] in resources:
			resources[resource[1]] = byte_count
		else:
			resources[resource[1]] += byte_count

	top_10 = sorted(resources.iteritems(), key=lambda x:-x[1])[:10]

	with open(resources_file, 'wb') as f:
		for x in top_10:
			f.write(x[0]+'\n')

# Helper function to calculate if two timestamps are within an hour of each other
def within_an_hour(time1, time2):
	diff = (time2 - time1).total_seconds()
	if diff < 3600:
		return True
	else:
		return False

# Function to identify the 10 busiest 60 minute windows
# Two pointers to the input file are maintained. At any given moment, the logs between the start and the end 
#      pointers lie within a 60 minute window. When the next entry does not lie in this window, the pointer are incremented accordingly
def busiest_windows(logs, hours_file):
	timestamps = dict()
	fmt = '%d/%b/%Y:%H:%M:%S'

	count = 1
	start = 0
	end = 0

	while end < len(logs) - 1  and start < len(logs) - 1 :
		start_time = datetime.strptime(logs[start].split()[0], fmt)
		end_time = datetime.strptime(logs[end].split()[0], fmt)

		if within_an_hour(start_time, end_time):
			count += 1
			end += 1

		else:
			count -= 1
			if logs[start] in timestamps:
				timestamps[logs[start]] = max(timestamps[logs[start]], count) 
			else:
				timestamps[logs[start]] = count 
			start += 1

	while start <= end:
		start_time = datetime.strptime(logs[start].split()[0], fmt)
		end_time = datetime.strptime(logs[end].split()[0], fmt)
	
		if within_an_hour(start_time, end_time):
			if logs[start] in timestamps:
				timestamps[logs[start]] = max(timestamps[logs[start]], count) 
			else:
				timestamps[logs[start]] = count
			count -= 1
		else:
			count -= 1
			if logs[start] in timestamps:
				timestamps[logs[start]] = max(timestamps[logs[start]], count) 
			else:
				timestamps[logs[start]] = count
		start += 1

	top_10 = sorted(timestamps.iteritems(), key=lambda x:-x[1])[:10]

	with open(hours_file, 'wb') as hours:
		for x in top_10:
			hours.write("{0},{1}\n".format(*x))

# Function to detemine logs that need to be blocked
def failed_login_attempts(parsed_data, raw_data, blocked_file):
	ip_to_block = defaultdict(dict)
	fmt = '%d/%b/%Y:%H:%M:%S'

	try:
		if os.path.exists(blocked_file):
			os.remove(blocked_file)
	except Exception as e:
		pass

	for log in range(len(parsed_data)):
		try:
			ip = parsed_data[log][0]
			status_code = parsed_data[log][3]
		except:
			continue

		if status_code == '401':			
			if not ip in ip_to_block:
				first_timestamp = parsed_data[log][1].split()[0]
				ip_to_block[ip]['timestamp'] = datetime.strptime(first_timestamp, fmt)
				ip_to_block[ip]['count'] = 1
				ip_to_block[ip]['diff'] = 0
			else:
				login_time = parsed_data[log][1].split()[0]
				login_timestamp = datetime.strptime(login_time, fmt)
				delta = (login_timestamp - ip_to_block[ip]['timestamp']).total_seconds()

				if ip_to_block[ip]['count'] == 3:
					
					if delta <= 300:
						with open(blocked_file, 'a') as f:
							f.write(raw_data[log])
					else:
						ip_to_block[ip]['timestamp'] = datetime.strptime(login_time, fmt)
						ip_to_block[ip]['count'] = 1
						ip_to_block[ip]['diff'] = 0
				else:
					if (delta + ip_to_block[ip]['diff']) <= 20:
						ip_to_block[ip]['timestamp'] = datetime.strptime(login_time, fmt)
						ip_to_block[ip]['count'] += 1
						ip_to_block[ip]['diff'] = delta + ip_to_block[ip]['diff']
					else:
						if delta > 20:
							ip_to_block[ip]['timestamp'] = datetime.strptime(login_time, fmt)
							ip_to_block[ip]['count'] = 1
							ip_to_block[ip]['diff'] = 0
						else:
							ip_to_block[ip]['timestamp'] = datetime.strptime(login_time, fmt)
							ip_to_block[ip]['diff'] = delta
		else:
			if ip in ip_to_block and ip_to_block[ip]['count'] == 3:
				login_time = parsed_data[log][1].split()[0]
				login_timestamp = datetime.strptime(login_time, fmt)
				delta = (login_timestamp - ip_to_block[ip]['timestamp']).total_seconds()

				if delta <= 300:
					with open(blocked_file, 'a') as f:
						f.write(raw_data[log])

if __name__ == '__main__':
	# Command line arguments as input
	log_file = sys.argv[1]
	hosts_file = sys.argv[2]
	hours_file = sys.argv[3]
	resources_file = sys.argv[4]
	blocked_file = sys.argv[5]

	# lists to store the parsed_data, raw_data and time_log
	parsed_data = list()
	raw_data = list()
	time_log = list()

	with open(log_file, 'rb') as f:
		lines = f.readlines()
		for line in lines:
			raw_data.append(line)
			line = line.strip().split(' ')

			host = line[0]

			timestamp = line[3].replace('[','') + ' ' + line[4].replace(']','')

			# Encode all strings as ascii as we might encounter weird symbols
			try:				
				request_type = line[5].decode("utf-8").encode("ascii", "ignore").replace('"', '')
				request_url = line[6]
				request_proto = line[7].decode("utf-8").encode("ascii", "ignore").replace('"', '')
				request_body = request_type + ' ' + request_url + ' ' + request_proto
				status = line[8]
			except:
				continue

			# some events do not have a byte count. If we encounter such events the byte count is treated as 0
			try:
				if len(line) != 10:
					line.append(int(0))
				if line[9] == '-':
					line[9] = int(0)
				byte_count = int(line[9])
			except ValueError:
				byte_count = int(0)

			# Put them all in a list so that it becomes easier to access and work with
			data = [host, timestamp, request_body, status, byte_count]
			time_log.append(timestamp)
			parsed_data.append(data)

	top_active_addresses(parsed_data, hosts_file)
	print "Completed feature one"
	bw_intensive_resources(parsed_data, resources_file)
	print "Completed feature two"
	busiest_windows(time_log, hours_file)
	print "Completed feature three"
	failed_login_attempts(parsed_data, raw_data, blocked_file)
	print "Completed feature four"
