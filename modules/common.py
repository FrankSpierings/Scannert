import re

def target_to_filename(target):
    return re.sub('[^a-zA-Z0-9-_.]', '_', target)

def is_ipaddress(target):
	pattern = '^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
	r = re.search(pattern, target)
	if (r):
		octets = [int(i) for i in r.groups()]
		for octet in octets:
			if (octet > 255) or (octet < 0):
				return False
		return True
	else:
		return False