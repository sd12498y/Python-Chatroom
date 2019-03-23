#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:

##Hi
from tkinter import *
import sys
import socket
import threading
import time
import select

#
# Global variables
#
username = ""
serverPort = 32340
serverAddress = "localhost"
userAddress = 'localhost'
userPort = 32341
socketfd = None
isJoined = False #to check whether the user has already joined a chatroom
keepAlive = True
memberList = dict()
memberHash = None
joinedRoomName = ""
t1 = None
server_thread = None
RList = []
WList = []

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form a string that be the input 
# to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def do_User():
	tempName = userentry.get()
	global username
	outstr = "\n[User] username: "
	if (len(tempName) > 0 and not isJoined):
		if (not username):
			username = tempName
			outstr += username
		else:
			if(not tempName == username):
				oldName = username
				username = 	tempName
				outstr += "Changed from " + oldName + " to " + username
			else:
				outstr += "Remains the same as " + username
	else:
		if (isJoined):
			outstr += "Already joined a chatroom. Rejected"
		else:
			outstr += "Empty entry. Rejected"
	CmdWin.insert(1.0, outstr)
	
	userentry.delete(0, END)


def do_List():
	CmdWin.insert(1.0, "\nPress List")
	# create socket and connect to Comm_pipe
	global socketfd
	if not socketfd:
		socketfd = socket.socket()
		try:
			socketfd.connect((serverAddress, serverPort))
			print("My socket address is ", socketfd.getsockname())
		except socket.error as err:
			print("Connection error: " ,err)
			sys.exit(1)
	# send the message
	msg = "L::\r\n"
	try:
		socketfd.sendall(msg.encode('ascii'))
	except socket.error as err:
		print("Sending error: ", err)
	# receive the message
	rmsg = socketfd.recv(1024)
	dmsg = rmsg.decode('ascii')
	names = dmsg[2:-4].split(":")
	outstr = ""
	for name in names:
		if name:
			outstr += name + ","
	CmdWin.insert(1.0, "\n[List] list of chatrooms: " + outstr)





def do_Join():
	global isJoined,socketfd,joinedRoomName, keepAlive,t1,memberList,memberHash,server_thread
	CmdWin.insert(1.0, "\nPress JOIN")
	if not username:
		CmdWin.insert(1.0, "\n[JOIN] Request rejected.You should register a username first.")
		return
	if isJoined:
		CmdWin.insert(1.0, "\n[JOIN] Request rejected.You have already joined a chatroom.")
		return
	#get the target chatroom name from the entry
	roomName = userentry.get()
	if not roomName:
		CmdWin.insert(1.0, "\n[JOIN] Request rejected. Please enter your target chatroom name.")
		return
	if not socketfd:
		socketfd = socket.socket()
		try:
			socketfd.connect((serverAddress, serverPort))
		except socket.error as err:
			print("Connection error: " ,err)
			sys.exit(1)
	# send the message
	rm = ":" + roomName
	un = ":" + username
	ip = ":" + userAddress
	pt = ":" + str(userPort)
	msg = "J" + rm + un + ip + pt + "::\r\n"
	try:
		socketfd.sendall(msg.encode('ascii'))
	except socket.error as err:
		print("Sending error: ", err)
	# receive the message
	rmsg = socketfd.recv(1024)
	if rmsg:
		dmsg = rmsg.decode('ascii')
		joinedRoomName = roomName
		members = dmsg[2:-4].split(":")
		memberHash = members[0]
		memberList = create_member_record(members[1:])
		isJoined = True
		keepAlive = True
		t1 = threading.Thread(target=keep_alive,args=(msg,))
		t1.daemon = True
		t1.start()
		server_thread = threading.Thread(target=run_server)
		server_thread.daemon = True
		server_thread.start()

	userentry.delete(0, END)

def create_member_record(members):
	tempRecord = dict()
	outstr = ''
	for i in range(0,len(members)-2,3):
		tempRecord[members[i]] = (members[i+1],int(members[i+2]))
		print(tempRecord[members[i]])
		outstr += members[i] + ', '
	CmdWin.insert(1.0, "\nMember in chatroom " + joinedRoomName + ": " + outstr)
	return tempRecord

def keep_alive(msg):
	global memberHash, memberList
	while True:
		if not keepAlive:
			return
		try:
			socketfd.sendall(msg.encode('ascii'))
		except socket.error as err:
			print("Sending error: ", err)
		# receive the message
		rmsg = socketfd.recv(1024)
		if rmsg:
			dmsg = rmsg.decode('ascii')
			members = dmsg[2:-4].split(":")
			if memberHash == members[0]:
				pass
				#CmdWin.insert(1.0, "\nNo new member in the chatroom.")
			else:
				memberHash = members[0]
				memberList = create_member_record(members[1:])
				dmsg = rmsg.decode('ascii')
				print(dmsg)
		time.sleep(20)
		

def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


def do_Poke():
	global memberList
	CmdWin.insert(1.0, "\nPress Poke")
	target = userentry.get()
	if isJoined:
		if target:
			if target != username:
				if target in memberList:
					print("found it!")
					temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					msg = 'K:' + joinedRoomName + ':' + username+'::\r\n'
					temp_socket.sendto(msg.encode('ascii'),memberList[target])
					temp_socket.settimeout(2)
					try:
						rmsg, peerAddress = temp_socket.recvfrom(64)
					except socket.timeout:
						CmdWin.insert(1.0, "\nDid not receive ACK from the peer.")
					CmdWin.insert(1.0, "\n" + target + " has received your poke;)")
					temp_socket.close()

			else:
				CmdWin.insert(1.0, "\nError: You can't poke youself.")
		else:
			CmdWin.insert(1.0, "\nError: Please enter a valid name.")
			outstr = ''
			for member in memberList:
				outstr += str(member) + ', '
			CmdWin.insert(1.0, "\nValid name are: " + outstr)
	else:
		CmdWin.insert(1.0, "\nError: Please join a chatroom first.")
	
	userentry.delete(0, END)
	
def run_server():
	socketUdpReceiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socketUdpReceiver.bind((userAddress,userPort))
	RList = [socketUdpReceiver]
		# start the main loop
	while True:
		# use select to wait for any incoming connection requests or
		# incoming messages or 10 seconds
		try:
			Rready, Wready, Eready = select.select(RList, [], [], 10)
		except select.error as emsg:
			print("At select, caught an exception:", emsg)
			sys.exit(1)
		except KeyboardInterrupt:
			print("At select, caught the KeyboardInterrupt")
			sys.exit(1)

		# if has incoming activities
		if Rready:
			# for each socket in the READ ready list
			for sd in Rready:

				# if the listening socket is ready
				# that means a new connection request
				# accept that new connection request
				# add the new client connection to READ socket list
				# add the new client connection to WRITE socket list
				if sd == socketUdpReceiver:
					(rmsg, peerAddress) = socketUdpReceiver.recvfrom(64)
					dmsg = rmsg.decode('ascii')
					info = dmsg[2:-4].split(':')
					print(dmsg)
					print(peerAddress)
					msg = b'A::\r\n'
					CmdWin.insert(1.0, "\n" + info[1] + " just poke you;)")
					socketUdpReceiver.sendto(msg,peerAddress)

		# else did not have activity for 10 seconds, 
		# just print out "Idling"
		else:
			print("Server Idling")



def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	global keepAlive,t1
	keepAlive = False
	#if t1:
	#	t1.join()
	sys.exit(0)


#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)
	global serverPort, serverAddress, userPort
	try:
		serverPort = int(sys.argv[2])
	except:
		serverPort = 32340
	try:
		serverAddress = sys.argv[1]
	except:
		serverAddress = 'localhost'
	try:
		userPort = int(sys.argv[3])
	except:
		userPort = 32341


	win.mainloop()

if __name__ == "__main__":
	main()

