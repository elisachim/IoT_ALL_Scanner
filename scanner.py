''' latest version of the IoT scanner updated 26.04.2020'''

#scanner.py
''' 
Ussage:				This is a python scripy developed in order to scan networks for vulnerabilities 
					in regards to the ussage of default, factory set credentials. 
Developed by: 		Elis Achim
Created: 			January 2020
Requirements: 		Shodan (refer to requirments file) 
Assumptions made: 	The local network utilises a /24 subnet

'''

# Importing libraries needed. Do not forget to install shodan (pip install shodan)
import socket
import subprocess
import shodan
import urllib2
import telnetlib
import paramiko
import os
import re
import sys
import time
import Queue
import getpass
import tkMessageBox
import ttk
import base64
import webbrowser
from contextlib import contextmanager
from Tkinter import *
from socket import *
from datetime import datetime
from threading import Thread
from ScrolledText import *
from ftplib import FTP


# Below there is a list of the passwords used in the Mirai attack back in 2016
users = ['login','guest','toor','','root','00000000','1111111','1111','1234','12345','123456','54321','666666','7ujMko0','7ujMko0admin','7ujMko0vizxv','meinsm','changeme','888888','admin','anko','default','dreambox','hi3518','ikwb','juantech','jvbzd','klv123','klv1234','pass','password','realtek','system','user','vizxv','xc3511','xmhdipc','zlxx.','Zte521','service ','service','smcadmin']
root_user = ['root', 'toor', 'user', 'guest', 'login', 'changeme', '666666', '888888', 'fucker', 'supervisor', 'support', 'tech', 'ubnt', '1234', 'admin', 'password', 'user', '12345', '123456', 'default', 'pass', 'password']


# The list contains Murai attack default login names
mirai_name = ['login','root','666666','888888','mother','supervisor','support','tech','ubnt','user','guest','administrator','Administrator','admin1','admin','pi']

'''Telnet login function attempts a login into a device using mirai credential list. 
 Gets value for user name, password and host ip passed to it. 
 ''' 
def telnet(usr,pwd,host):
	tn = telnetlib.Telnet(host,23,2)
	tn.read_until("login: ",2)
	tn.write(usr + '\n')
	if pwd:
		tn.read_until("Password: ",2)
		tn.write(pwd + "\n")
	tn.write("ls\n")
	tn.write("exit\n")
	tn.read_all()
	x = 'Host: ' + host + ' has been found as vulnerable. The user name is: ' + usr + ' The password is: ' + pwd
	tn.close()
	return(x)

def ssh(usr, pwd, host):
	ssh = paramiko.SSHClient()
	if ssh.connect(host, username=usr, password=pwd):
		ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("ls\n")
		ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("exit\n")
		x = 'Host: ' + host + ' is vulnerable. The user name is: ' + usr + ' The password is: ' + pwd
	else:
		x = 'Host: ' + host + ' could not be connected to.'
	return(x)

def ftp(usr, pwd, host):
	ftp = ftplib.FTP(host)
	if ftp.login(user=usr, passwd = pwd):
		x = 'Host: ' + host + ' is vulnerable. The user name is: ' + usr + ' The password is: ' + pwd
	ftp.quit()
	return (x)

''' 
Bruteforce function. 
Passes the mirai credentials to TELNET, SSH respectively FTP functions above,
along with the ip address for the login attempt.
'''
def brute_force(host):
	y = 0
	port = 23
	for name in mirai_name:
		user = name
		if user == 'root':
			for password in root_user: # looping through all lists of users and passwords
				try:
					tel = telnet(user, password, host)	# call the telnet login funciton for one user at a time		
				except:
					pass
				try:
					ss = ssh(user, password, host)	# call the ssh login funciton for one user at a time
				except:
					pass
				try:
					ft = ftp(user, password, host)		# call the ftp login funciton for one user at a time	
				except:
					pass
		else:
			for password in users:
				try:
					y = telnet(user, password, host)
				except:
					pass
				try:
					ss = ssh(user, password, host)	
				except:
					pass
				try:
					ft = ftp(user, password, host)			
				except:
					pass
	y = tel + '\n'+ ss + '\n' + ft + '\n'
	return y

def telnet_external(host):
	y = 0
	port = 23
	for name in mirai_name:
		user = name
		if user == 'root':
			for password in root_user:
				try:
					y = telnet(user, password, host)					
				except:
					pass
		else:
			for password in root_user:
				try:
					y = telnet(user, password, host)					
				except:
					pass
	return y


# function that gets the ip address of main interface
def get_ip_address():
    s = socket(AF_INET, SOCK_DGRAM) 				# Set up a socket
    s.connect(("8.8.8.8", 80)) 	
    return s.getsockname()[0]  						# Return the ip address of the interface used in attempt to connect to google

'''
Function to get listening devices IP address range. Assumes /24 for home network. 
Gets the first three octets of internal ip address then scans the entire range for replys 
The host ip is being passed into it to get first 3 octects
'''
def iprange_ping(hostip):
	full_ips = []
	net_range = hostip[:hostip.rfind(".")] 			# Gets the first 3 octets
	net_range = net_range + '.'
	with open(os.devnull, "wb") as limbo:  			# os.devnull writes results to null device and only records the visit
		for n in xrange(1, 255):					# Range for last octet without the first and last one
			full_ip = net_range + "{0}".format(n)
			result = subprocess.Popen(["ping", "-n", "1", "-w", "400", full_ip], stdout=limbo, stderr=limbo).wait() # Ping range, each ip will get 1 ping (-n), and 400 mSec wait for no reply (-w) 
			if result:
				pass
			else:
				full_ips.append(full_ip)   			# List enclosing ips. will be the keys for address:port dictionary
	return full_ips

'''
First port scan function. 
Scans each listening IP address for active ports. 
Each  of the 4 threads scans 1/4 of the ip range from 1 to 6000
Next function is the 5th thread scanning popular ports above 6000
'''
def scan_host(host, port_start, port_end, queue):
	open_ports = [] 							# Set up list
	r_code = 1 									# Set default r_code value
	for port in range(port_start,port_end):
		try:
			a = socket(AF_INET,SOCK_STREAM)
			a.settimeout(.07)                   # Timeout for socket to connect
			code = a.connect_ex((host, port))
			if code == 0:						# If port is open
				r_code = code
				open_ports.append(port) 		# Add port number to list
				a.close() 						# Close port
		except Exception, e:
			pass
	queue.put(open_ports)  						# Method of returning value from threads.
'''
Second port scan function
Scans each listening IP address for active ports. 
A fifth thread scanning a list of popular ports
'''
def scan_popular(host, port_list, queue):
	open_ports = [] 		
	r_code = 1 	
	for port in port_list:
		try:
			a = socket(AF_INET,SOCK_STREAM)
			a.settimeout(.07)                   # Timeout for socket to connect
			code = a.connect_ex((host, port))
			if code == 0:						# If port is open
				r_code = code
				open_ports.append(port) 		# Add port number to list
				a.close() 						# Close port
		except Exception, e:
			pass
	queue.put(open_ports)  						# Method of returning value from threads.

''' 
Function sets up threading to speed up port scan. 
Uses 5 threads and each thread stores its result in queue()
After the threads are have completed they are re-joined and the values are retrieved from queue()
The list of popular ports above 6000 is dor the 5th thread
'''
def port_scan(ip_list):
	openports = []
	port_list = ['6129', '6667', '6670', '6711', '6901', '6969', '6970', '7000', '8000', '8080', '8886', '8767', '8866', '9119', '9898', '9988', '10000', '10008', '12035', '12036', '12345', '12456', '14567', '15118', '17200', '17300', '21554', '22136', '22222', '24800', '25999', '27015', '27374', '28960', '29559', '31337', '31338', '65506'] 
	init_scan_data = {} 												# Set up dictionary
	q1 = Queue.Queue() 													# Set up queue to store results from threads
	q2 = Queue.Queue()
	q3 = Queue.Queue()
	q4 = Queue.Queue()
	q4 = Queue.Queue()
	for item in ip_list: 												# For ip found, scan for ports
		host = item 
		thread1 = Thread(target=scan_host, args=(host, 1, 1500, q1))   	# Create the 5 threads
		thread2 = Thread(target=scan_host, args=(host, 1501, 3000, q2))
		thread3 = Thread(target=scan_host, args=(host, 3001, 4500, q3))
		thread4 = Thread(target=scan_host, args=(host, 4501, 6000, q4))
		thread5 = Thread(target=scan_popular, args=(host, port_list, q5))
		thread1.start() 												# Start threads
		thread2.start()
		thread3.start()
		thread4.start()
		thread5.start()
		thread1.join()						
		thread2.join()
		thread3.join()
		thread4.join()
		thread5.join()
		openports = q1.get() + q2.get() + q3.get() + q4.get() + q5.get()		#results from port scan are joined together
		init_scan_data[host] = openports 								# Fill dictionary with results
	return init_scan_data

# Obtaining external IP address using shodan api
def get_external_ip(shodan_api):
	try:
		externalip = urllib2.urlopen('https://api.shodan.io/tools/myip?key={' + shodan_api + '}') 
		extip = externalip.read()
		result = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', extip ) # get the ip address
		result = str(result[0])
		return result
	except Exception, e:
		x = 0
		return x

# Function to test a single host for mirai vulnerabilities
def internal_test_function(app, progress, label2text, label2, user_view):
	vulnerable = 0
	op = open('Report.txt','a') 						# Open Report.txt for adding results
	x = " \n --- This is the internal network scan --- \n \n Started At: %s\n" % (time.strftime("%H:%M:%S")) 
	op.write(x)
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	x = '''

-----------------
  Internal Scan 
-----------------

We have started the process of scanning your 
internal network for any vulnerabilities.

This scan checks your local network for open ports
and checks any device open for services avalaible.

You can find below all the details regarding the
scan along with the results, which will also be 
saved in the Report.txt file.


'''
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	tkMessageBox.showinfo("The IOT Vulnerability Scanner ", 
'''Before running the test please read the 
following notices, then click 'Start'

1. 	Disconnect the cable connecting 
	your main router to the internet.

2. 	After removing it, please reboot
	all your devices connected to 
	that access point.

The reason for doing this is that some 
IOT malware such as Mirai are removed 
by rebooting your devices.

These malware samples are capable of 
re-infecting devices in about 2 minutes. 
In the meanwhile our scan will proceed.

You will have in the column on the right
all the details as the test goes along.

3. 	Press 'Enter' on your keyboard to proceed


''') 												# pause here util user ready
	x = '\n\nScanning for vulnerabilities...\n'
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	op.close()
	label2 = Label(app, textvariable=label2text, fg="blue").grid(row=480,column=2, sticky=N)
	progress.start(1)
	thread6 = Thread(target=internal_scan, args=(app, progress, label2text, label2, user_view))
	thread6.start()
	
			
def internal_scan(app, progress, label2text, label2, user_view):
	op = open('Report.txt','a')
	start_time = datetime.now()
	address = get_ip_address() 							# Get private ip address 
	ip_list = iprange_ping(address) 					# Get list of available private ip addresses
	scan_result = port_scan(ip_list) 					# Get scan results of internal ip addresses and open ports
	x = '''

-------------------
  IP & Ports Scan 
-------------------
'''
	op.write(x)
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	x = "\nIP Address of the main interface: " + str(address) 
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	for keys,values in scan_result.items():  			# display and save the scan result to Report.txt
		y = "\nIP addresses and open ports on these devices:  \n " + str(key) +  str(":") + str(values)
		user_view.configure(state='normal')
		user_view.insert(INSERT, y)
		op.write(x)
		op.write(y)
		user_view.configure(state='disabled')
		user_view.insert(INSERT, x)
		user_view.insert(INSERT, y)
		user_view.configure(state='disabled')
	x = '''

--------------------------------------
  Attempting a brute-force intrusion 
--------------------------------------
'''
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='normal')
	for keys,values in scan_result.items(): 				# This gives out each key with a list of its values
		for item in values:
			if item == 23:
				x = '\nScanning ' + keys + ' for Mirai vulnerability\n'
				user_view.configure(state='normal')
				user_view.insert(INSERT, x)
				user_view.configure(state='normal')
				vulnerable = brute_force(keys)
				if vulnerable != 0:
					conf = open('conf.cfg','a')
					conf.write(vulnerable)
					conf.close()
					x = '''	Device is vulnerable to a Mirai attack

Please make sure you contact a security specialist,
one that can either change the passwords on your devices
as they are vulnerable to a brute-force attack, or they 
can close the vulnerable ports. 							
It is still recommended that you change the passwords on
your devices nevertheless.
You can also provide the specialist with the report saved
on your computer, having all the details of this scan.

If you, however decide to act by yourself, in the meantime,
here are a few recommendations:

1. Please use complicated passwords including a combination
   of letters, numbers and symbols.
2. Use different passwords for each device.
3. Back up all important information.
4. Do not download files illegally.
							'''
					op.write(vulnerable)
					user_view.configure(state='normal')
					user_view.insert(INSERT, vulnerable)
					user_view.configure(state='normal')
				else:
					x = '\n Device not vulnerable to a Mirai attack'
					op.write(x)
					user_view.configure(state='normal')
					user_view.insert(INSERT, x)
					user_view.configure(state='normal')
		else:
			pass
	stop_time = datetime.now()
	total_time_duration = stop_time - start_time
	x = "\n\nScanning Finnished At %s..." %(time.strftime("%H:%M:%S"))
	y = "\nScanning Duration: %s..." %(total_time_duration)
	z = "\n\nScanning finished. You can now connect your router back to the internet."
	op.write(x)
	op.write(y)
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.insert(INSERT, y)
	user_view.insert(INSERT, z)
	user_view.configure(state='disabled')
	op.close()
	progress.stop()
	label2 = Label(app, textvariable=label2text, state= DISABLED, fg="blue").grid(row=480,column=2, sticky=N)
	
	
		
# Function displays the total number of avaible IP address	
def external_scan_function(app, progress, label2text, label2, user_view):
	op = open('Report.txt','a') 						# Open Report.txt for adding results
	x = '''

-----------------
  External Scan 
-----------------

We have started the process of scanning your 
external network for open ports and services
login vulnerabilities.

This scan is using Shodan's online database
for any information available about your network.

You can find below all the details regarding the
scan along with the results, which will also be 
saved in the Report.txt file.


'''
	op.write(x)
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	tkMessageBox.showinfo(" The IOT Vulnerability Scanner",
'''
Welcome to the Shodan x IoT Scanner All
intergration.

First off, before running this scan, please make
sure your router is connected to 
the internet.

This scan is using Shodan's online 
database for any information available
about your network.

You will have in the column on the right
all the details as the test goes along.

Press 'Enter' on your keyboard to proceed

	''')					# pause here until user is ready and presses 'Enter' or 'OK'
	x = '\n\nScanning for vulnerabilities...\n'
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	op.close()
	thread7 = Thread(target=external_scan, args=(app, progress, label2text, label2, user_view))
	label2 = Label(app, textvariable=label2text, fg="blue").grid(row=480,column=2, sticky=N)
	progress.start(1)
	thread7.start()
	

def external_scan(app, progress, label2text, label2, user_view):
	op = open('Report.txt','a')
	vulnerable = 0
	x = "\nStarted At: %s\n" % (time.strftime("%H:%M:%S")) # Time scan started
	op.write(x)
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	start_time = datetime.now()
	x = '''
---------------	
  Shodan Scan 
---------------
'''
	op.write(x)
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')
	ak = open('conf.cfg','r')
	api_key = ak.read()
	ak.close()
	try:
		api_key = api_key.split()
		shodan_api_key = api_key[-1] 
		api_key = shodan.Shodan(shodan_api_key)
		ip = get_external_ip(shodan_api_key)
		x = '\nYour external IP is: ' + ip + '\nWe are now checking Shodan for your external address...'
		op.write(x)
		user_view.configure(state='normal')
		user_view.insert(INSERT, x)
		user_view.configure(state='disabled')
		try:
			host = api.host(ip)
			x = "\nIP: %s \nService Provider: %s \nOperating System: %s" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))  # Print general info
			op.write(x)
			user_view.configure(state='normal')
			user_view.insert(INSERT, x)
			user_view.configure(state='disabled')
			for item in host['data']:
				x = "\nPort: %s Banner: %s" % (item['port'], item['data']) # Print all banners
				op.write(x)
				user_view.configure(state='normal')
				user_view.insert(INSERT, x)
				user_view.configure(state='disabled')			
		except Exception, e:
			x = '\n \nYour device could not be found on Shodan. This is a good thing.\n'
			op.write(x)
			user_view.configure(state='normal')
			user_view.insert(INSERT, x)
			user_view.configure(state='disabled')	
		x = ''' 
-----------------------------------
  Scanning your external IP for
known Mirai & QBOT vulnerabilities 
----------------------------------- '''
		vulnerable = 0
		user_view.configure(state='normal')
		user_view.insert(INSERT, x)
		user_view.configure(state='disabled')
		x = '\nScanning your routers external IP: ' + ip + ' for vulnerabilities\n'
		user_view.configure(state='normal')
		user_view.insert(INSERT, x)
		user_view.configure(state='disabled')
		vulnerable = telnet_external(ip)
		if vulnerable != 0:
			op.write(vulnerable)
			user_view.configure(state='normal')
			user_view.insert(INSERT, vulnerable)
			user_view.configure(state='disabled')
		else:
			x = '\nDevice not vulnerable to Mirai style attack'
			op.write(x)
			user_view.configure(state='normal')
			user_view.insert(INSERT, x)
			user_view.configure(state='disabled')
		stop_time = datetime.now()
		total_time_duration = stop_time - start_time
		x = "\n\nScanning has finnished at: %s..." %(time.strftime("%H:%M:%S"))
		y = "\nScan duration: %s..." %(total_time_duration)
		op.write(x)
		op.write(y)
		user_view.configure(state='normal')
		user_view.insert(INSERT, x)
		user_view.insert(INSERT, y)
		user_view.configure(state='disabled')
		op.close()
		progress.stop()
		label2 = Label(app, textvariable=label2text, state= DISABLED, fg="blue").grid(row=480,column=2, sticky=N)
	except:
		x = '''
Warning - There is no API key 
present!

Please get Shodan api key and 
insert it in the box provided 
for the scan to work.'''
		op.write(x)
		user_view.configure(state='normal')
		user_view.insert(INSERT, x)
		user_view.configure(state='disabled')
		op.close()
		progress.stop()
		label2 = Label(app, textvariable=label2text, state= DISABLED, fg="blue").grid(row=480,column=2, sticky=N)
	
# Function to explain about the software
def about_function():
	x = ''' 
		About the IOT Vulnerability Scanner
		
The IoT All Scanner has been created as a masters year project by the Cybersecurity MSc student Elis Achim 
It's main functionality is to test your network for vulnerabilities involving IoT devices. 
This includes internet connected devices, such as seucrity systems, routers, web cams, raspberry pi's, etc.
It has been created in such a manner, so that everyone can use this device, without the need of any security based training.
This tool has been specifically crafted for people travelling around, hoping from a network to another one, 
aiming at remaining secure when connecting to a new unsecured network.

The tool has two main functionalies, as presented on the left hand side:

1. The INTERNAL network scan:

1. It will find out your IP address.
2. It will scan your network range for active host (assumes the user is on a /24 subnet).
3. For every device found active it will check for open ports, scanning the ports 1 - 6000 plus a few other popular ones.
4. For every open port, it will attempt a brute-force connection using a list of default and commonly used passwords.
5. Finally, it will set up a report based on the results found and it will appear on your screen as well as in a text file saved as report.txt.
	

For the EXTERNAL scan:

1. When using this feature for the first time, please click the 'Get your own SHODAN API key here', which will take you on Shodan's website.
2. Create an account and copy the given key into the box provided in the software.
3. Click on 'Use the key', and then run the External Scan.
4. It will scan your external IP against Shodan's database.

In order to achieve the best results:

Please carefuly read the on screen instructions during each scan, as the program will prompt the user for certain actions.
'''
	user_view.configure(state='normal')
	user_view.insert(INSERT, x)
	user_view.configure(state='disabled')


# the widget that takes in users shodan code
def shodan_user():
	conf = open('conf.cfg','w')
	x = 'Insert Shodan API key: ' + shodan_code_entry.get() + '\n'
	conf.write(x)
	conf.close()

# link to Shodan developer to get API key
def OpenUrl():
    webbrowser.open_new('https://developer.shodan.io/')


def menu(opt):
	user_view.configure(state='normal')
	user_view.delete(1.0,END)
	user_view.configure(state='disabled')
	if opt == 1:
		internal_test_function(app, progress, label2text, label2, user_view)
	elif opt == 2:
		external_scan_function(app, progress, label2text, label2, user_view)
	elif opt == 3:
		about_function()
	elif opt == 5:
		shodan_user()
	elif opt == 6:
		sys.exit()

	



#### ******* Main Code Calls and GUI using Tkinter ******* ####

#  text file set up that stores the final results
try:
	conf = open('conf.cfg','r')
except:
	conf = open('conf.cfg','w')
op = open('Report.txt','w')
now = time.strftime("%c")
user = getpass.getuser()
x = ' ------------------------------------   \n IOT Scanner Final Report  \n ------------------------------------ \n\n Scanner has been ran on: ' + now + '\nThe logged in user is: ' + user + '\n'
op.write(x)
op.close()
conf.close()

'''
GUI design part using Tkinter
'''
# set up app frame and name	
app = Tk()
app.title("The IOT Vulnerability Scanner - Ellis ")
app.geometry('1150x800')

# Labels above buttons

label0text = StringVar()
label0text.set("   Welcome to IoT All Scanner")
label0 = Label(app, textvariable=label0text, font='Lato 22 bold', fg="#2FA8E2").grid(row=100,column=1, sticky=N, columnspan=3)
label1text = StringVar()

# Set of instructions on the right hand side of the buttons
# 1. Internal Scan

label1txt = StringVar()
label1txt.set("Will scan your network range for active host")
label1 = Label(app, textvariable=label1txt, font='Lato 12', fg="black").grid(row=300,column=2, sticky=W)
label1text = StringVar()

label2text = StringVar()
label2text.set("For every open port, it will attempts a brute-force")
label2 = Label(app, textvariable=label2text, font='Lato 12', fg="black").grid(row=305,column=2, sticky=W)
label1text = StringVar()

''' Design too crowded. Part removed on the 02.06.2020
label3text = StringVar()
label3text.set("attack for multiple services available. ")
label3 = Label(app, textvariable=label3text, font='Lato 12', fg="black").grid(row=305,column=2, columnspan=1)
label1text = StringVar()
'''

# 2. External Scan

label4text = StringVar()
label4text.set("If first time, please use the options below.")
label4 = Label(app, textvariable=label4text, font='Lato 12', fg="black").grid(row=450,column=2, sticky=W)
label1text = StringVar()

label5text = StringVar()
label5text.set("Will scan your external IP against Shodan's database.")
label5text = Label(app, textvariable=label5text, font='Lato 12', fg="black").grid(row=455,column=2, sticky=W)
label1text = StringVar()

'''  # design too crowded --- removed on the 02.06.2020
label6text = StringVar()
label6text.set("All results saved to report.txt")
label6 = Label(app, textvariable=label6text, font='Lato 12', fg="black").grid(row=455,column=2, columnspan=1)
label1text = StringVar()
'''

# set the buttons
q6 = Queue.Queue()
button1 = Button(app, text="1. Internal Scan", font='Baloo 19', bg='blue', fg='white', width=15, command=lambda: menu(1)) # width=15, fg="white",bg='#2FA8E2',bd=5,relief='raised'
button1.grid(row=300,column=1, sticky=N, columnspan=1)

button2 = Button(app,
				text="2.External Scan",
				font='Baloo 19',
				fg="red" ,
				width=15,
				bg='red',
				command=lambda: menu(2))
button2.grid(row=450,column=1, columnspan=1)

button3 = Button(app,
				text="More details",
				font='Lato 20',
				width=15, 
				bg='green', 
				command=lambda: menu(3))
button3.grid(row=970,column=1, sticky=N, columnspan=2)

button4 = Button(app,
				text="Get your own Shodan API key here",
				font='Lato 15',
				bg='blue', 
				fg='yellow', 
				command=OpenUrl)
button4.grid(row=680, column=1, sticky=N, columnspan=2)

button5 = Button(app,
				text="Use the key ", 
				font='Lato 15',
				width=15,
				bg='green', 
				command=lambda: menu(5))
button5.grid(row=602,column=3, sticky=W, columnspan=1)

button6 = Button(app,
				text="Exit App", 
				font='Lato 20',
				width=15,
				bg = 'blue',
				fg = 'red', 
				command=lambda: menu(6))
button6.grid(row=1000,column=1, sticky=N, columnspan=2)



# set up the text widget
user_view = ScrolledText(app, width=60, height=45, wrap=WORD)
user_view.grid(row=0, column=4, rowspan = 1000)
user_view.configure(state='normal')
x = ''' 
	Welcome to the IOT Vulnerability Scanner

This is version number 3.1 of the Scanner. 
This tool has been created as a final year project by 
the Cybersecurity MSc student Elis Achim.


In order to start nay of the tests, please select one of 
the buttons on the left in order to test your network 
for vulnerabilities in regards to your IOT devices.

For more information about this software as well as 
step by step instructions on how to use it please click 
the 'About' button.



-----------------------
 General security Tips
-----------------------

1. Please always keep your personal devices up to date with 
   the latest firmware available, in order to 
   remain secured and receive any manufacturer security
   enhancements.
2. Upon purcahse, please change default passwords to all 
   of your devices.
3. Please use complex passwords, including a combination
   of letters, numbers and symbols.
4. Use different passwords for each device and each platform.
5. Back up all important information.
6. Do not download files illegally.


 Thank you for using IoT All Scanner.'''
user_view.insert(INSERT, x)
user_view.configure(state='disabled')

# loading bar
progress = ttk.Progressbar(app, orient='horizontal',length=300, mode='indeterminate')
progress.grid(row=800,column=1, sticky=N, columnspan=2)
label2text = StringVar()
label2text.set("Scanning In Progress")
label2 = Label(app, textvariable=label2text, state= DISABLED, fg="#2FA8E2").grid(row=790,column=1, sticky=N, columnspan=2)

# shodan api code entry field
label3text = StringVar()
label3text.set("Shodan API KEY - required when using External scan for the first time only.")
label3 = Label(app, textvariable=label3text, fg="#2FA8E2").grid(row=600,column=1, columnspan=2, sticky=N)
shodan_code_entry = Entry(app, exportselection=0, justify=LEFT, width = 40 )
shodan_code_entry.grid(row=602,column=1, columnspan=2, sticky=N)


# set up loop so program runs
app.mainloop()
