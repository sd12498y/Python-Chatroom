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

#user stuff
myUsername = ""
myHashID = None
myAddress = 'localhost'
myPort = 32341
isJoined = False #to check whether the user has already joined a chatroom
keepAlive = True
roomMemberDict = dict() #data structure = myUsername: (ip, port)

#chatroom stuff
roomMemberHash = None
joinedRoomName = ""


#theading stuff
keep_alive_thread = None
server_thread = None
connection_thread = None

#socket stuff
msgID = 0
serverPort = 32340
serverAddress = "localhost"
socketfd = None
forwardLinkedMember = ()
backwardLinkedMemberDict = dict()
RList = []
WList = []

#messging
messageCounter = dict()
#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's myUsername, str(IP address), 
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
	global myUsername, myHashID, myPort,myAddress
	outstr = "\n[User] username: "
	if (len(tempName) > 0 and not isJoined):
		if (not myUsername):
			myUsername = str(tempName)
			outstr += myUsername
			myHashID = sdbm_hash(myUsername+myAddress+str(myPort))
		else:
			if(not tempName == myUsername):
				oldName = myUsername
				myUsername = str(tempName)
				outstr += "Changed from " + oldName + " to " + myUsername
			else:
				outstr += "Remains the same as " + myUsername
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
	global isJoined,socketfd,joinedRoomName, keepAlive,keep_alive_thread,roomMemberDict,roomMemberHash,server_thread
	CmdWin.insert(1.0, "\nPress JOIN")
	if not myUsername:
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

	rmsg = joinRoom(roomName)
	# if the message is successfully received
	if rmsg:
		if(rmsg.decode("ascii")[0]=='M'):
			startServer()
			joinedRoomName = roomName #save the roomname to joinedRoomName
			roomMemberHash, membersInfo = decodeResponse(rmsg)
			roomMemberDict = create_member_record(membersInfo) #this is where we store the actual member info
			if (len(roomMemberDict)>1):
				create_forward_link()
			else:
				CmdWin.insert(1.0, "\n[JOIN]"+ " Chatroom " + joinedRoomName + " created")
				print("Chatroom " + joinedRoomName + " created")
			isJoined = True
			keepAlive = True
			startConnectionHandler()
			startKeepAlive()
	userentry.delete(0, END)

def startKeepAlive():
	# a new thread for keeping the connection between the peer and the server alive
	keep_alive_thread = threading.Thread(target=keep_alive)
	keep_alive_thread.daemon = True
	keep_alive_thread.start()

def startServer():
	#a new thread called server_thread is established for listening poke request
	server_thread = threading.Thread(target=run_server)
	server_thread.daemon = True
	server_thread.start()

def decodeResponse(rmsg):
	#decode the message
	dmsg = rmsg.decode('ascii')
	data_string = dmsg[2:-4].split(":") #generate a list of member in the rooms
	print(dmsg[0])
	if (dmsg[0] == 'M'):
		return data_string[0], data_string[1:] #roomHash, memberlist
	elif (dmsg[0] == 'A'):
		return data_string[0],data_string[1] #roomname, sendername
	elif (dmsg[0] == 'P'):
		return data_string[0], data_string[1], data_string[2], data_string[3], data_string[4]
	elif (dmsg[0] == 'T'):
		length = data_string[4]
		content = dmsg[-(int(length)+4):-4]
		return data_string[0], data_string[1], data_string[2], data_string[3],length, content
	elif (dmsg[0] == 'S'):
		return data_string[0]
	elif (dmsg[0] == 'K'):
		return data_string[0],data_string[1]


def updateMemberList():
	res = joinRoom(joinedRoomName)
	global roomMemberDict
	if res:
		tempHash, tempMember = decodeResponse(res)
		if (tempHash != roomMemberHash):
			roomMemberDict =  create_member_record(tempMember)

def joinRoom(roomName):
	global socketfd
	if not socketfd:
		socketfd = socket.socket()
		try:
			socketfd.connect((serverAddress, serverPort))
		except socket.error as err:
			print("Connection error: " ,err)
			sys.exit(1)
	# send the message
	rm = ":" + roomName
	un = ":" + myUsername
	ip = ":" + myAddress
	pt = ":" + str(myPort)
	msg = "J" + rm + un + ip + pt + "::\r\n"
	try:
		socketfd.sendall(msg.encode('ascii'))
	except socket.error as err:
		print("Sending error: ", err)
	# try to receive the message
	rmsg = socketfd.recv(1024)
	print(len(rmsg))
	if (len(rmsg)>0):
		return rmsg
	else:
		return None


def create_forward_link():
	tempList = list()
	for user in roomMemberDict.items():
		username = user[0]
		userIp = user[1][0]
		userPort = user[1][1]
		userHash = sdbm_hash(str(username) + str(userIp) + str(userPort))
		tempList.append((userHash,str(username), str(userIp), int(userPort)))
	tempList.sort(key=lambda tup: tup[0]) #sort by userHash
	print(tempList)
	start = (tempList.index((myHashID,myUsername,myAddress,myPort)) + 1) % len(tempList)
	while (tempList[start][0] != myHashID):
		if(tempList[start][1] in backwardLinkedMemberDict):
			start = (start + 1) % len(tempList)
		else:
			try:
				if (handshake(tempList[start])):
					print("Forward link successfully established. You are connected.")
					return
				else:
					start = (start + 1) % len(tempList)
			except socket.error as err:
				print(err)
	print(forwardLinkedMember)
	if (not forwardLinkedMember):
		print ("ERROR: Cannot establish TCP connection with Peer. System will start the connection procedure later")
		#TO-DO: reschedule the conneciton

def startConnectionHandler():
	#a new thread called server_thread is established for listening poke request
	connection_thread = threading.Thread(target=connectionHandling)
	connection_thread.daemon = True
	connection_thread.start()

def connectionHandling():
	#it runs only when it has joined a room
	global forwardLinkedMember
	while isJoined:
		if(len(roomMemberDict)>1):
			if (forwardLinkedMember):
				if(forwardLinkedMember[0] not in roomMemberDict):
					forwardLinkedMember = None
					print("WARNING: Your forward link has dismissed.")
			else:
				#user is disconnected
				print("WARNING: You have to connect to one forward link to make sure the system is working. System is reconnecting...")
				create_forward_link()
		time.sleep(1)

def handshake(user):
	# create socket and connect to Comm_pipe
	global forwardLinkedMember,RList,WList
	tempSocket = socket.socket()
	try:
		print(user)
		tempSocket.connect((user[2], int(user[3])))
		msg = 'P:' + joinedRoomName + ':' + myUsername+':' + myAddress +':' + str(myPort) +':' + str(msgID)+'::\r\n'
		tempSocket.sendall(msg.encode("ascii"))
		try:
			# receive the message
			rmsg = tempSocket.recv(50)
			mID = decodeResponse(rmsg)
			RList.append(tempSocket)
			WList.append(tempSocket)
			forwardLinkedMember = (user[1], tempSocket) #uss username as the key to find out the socket
			messageCounter[str(user[1])] = int(mID)
			return True
		except socket.error as err:
			print("Connection error: " ,err)
	except socket.error as err:
		print("Connection error: " ,err)
		sys.exit(1)
	return False


def create_member_record(raw_data_string):
	tempRecord = dict()
	outstr = ''
	for i in range(0,len(raw_data_string)-2,3):
		tempRecord[raw_data_string[i]] = (raw_data_string[i+1],int(raw_data_string[i+2])) # the data structure is a dictionary of tuples
		print(tempRecord[raw_data_string[i]])
		outstr += raw_data_string[i] + ', '
	CmdWin.insert(1.0, "\nMember in chatroom " + joinedRoomName + ": " + outstr)
	return tempRecord

def keep_alive():
	global roomMemberHash, roomMemberDict
	while True:
		if not keepAlive:
			return
		rmsg = joinRoom(joinedRoomName)
		if rmsg:
			dmsg = rmsg.decode('ascii')
			raw_data_string = dmsg[2:-4].split(":")
			if roomMemberHash == raw_data_string[0]:
				pass
				#CmdWin.insert(1.0, "\nNo new member in the chatroom.")
			else:
				roomMemberHash = raw_data_string[0]
				roomMemberDict = create_member_record(raw_data_string[1:])
				dmsg = rmsg.decode('ascii')
				print(dmsg)
		time.sleep(20)
		
def isConnected():
	return forwardLinkedMember or backwardLinkedMemberDict

def do_Send():
	msg = userentry.get()
	global myUsername, myHashID, myPort,myAddress,msgID
	if (len(msg) > 0):
		if(isJoined):
			if(isConnected()):
				msgID += 1
				fullMsg = "T:" + joinedRoomName + ":" + str(myHashID) + ":" + myUsername + ":" + str(msgID) + ":" + str(len(msg)) +":" + msg + "::\r\n"
				sendMessge(fullMsg)
				CmdWin.insert(1.0, "\n" +myUsername + ": " + msg)
			else:
				CmdWin.insert(1.0, "\nYou are disconnected right now. Can't send any message")
		else:
			CmdWin.insert(1.0, "\nPlease join a chatroom")
	else:
		CmdWin.insert(1.0, "\nERROR: Empty entry. Rejected")
	
	userentry.delete(0, END)
	


def do_Poke():
	global roomMemberDict
	CmdWin.insert(1.0, "\nPress Poke")
	target = userentry.get()
	if isJoined:
		if target:
			if target != myUsername:
				if target in roomMemberDict:
					print("found it!")
					temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					msg = 'K:' + joinedRoomName + ':' + myUsername+'::\r\n'
					temp_socket.sendto(msg.encode('ascii'),roomMemberDict[target])
					temp_socket.settimeout(2)
					try:
						rmsg, peerAddress = temp_socket.recvfrom(64)
						CmdWin.insert(1.0, "\n" + target + " has received your poke;)")
					except socket.timeout:
						CmdWin.insert(1.0, "\nDid not receive ACK from the peer.")
					temp_socket.close()

			else:
				CmdWin.insert(1.0, "\nError: You can't poke youself.")
		else:
			CmdWin.insert(1.0, "\nError: Please enter a valid name.")
			outstr = ''
			for member in roomMemberDict:
				outstr += str(member) + ', '
			CmdWin.insert(1.0, "\nValid name are: " + outstr)
	else:
		CmdWin.insert(1.0, "\nError: Please join a chatroom first.")
	
	userentry.delete(0, END)
	
def run_server():
	global RList, WList
	socketUdpReceiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socketUdpReceiver.bind((myAddress,myPort))
	socketTCPServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	socketTCPServer.settimeout(1.0)

	try:
		socketTCPServer.bind((myAddress,myPort))
		print("TCP server listening...")
	except socket.error as msg:
		print("Socket Bind Error: " + str(msg))
	# set socket listening queue
	socketTCPServer.listen(5)

	RList.append(socketUdpReceiver)
	RList.append(socketTCPServer)
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
					rmName, senderName = decodeResponse(rmsg)
					msg = b'A::\r\n'
					CmdWin.insert(1.0, "\n" + senderName + " just poke you;)")
					socketUdpReceiver.sendto(msg,peerAddress)
				elif sd == socketTCPServer:
					newfd, caddr = socketTCPServer.accept()
					print("TCP server receive connection request")
					RList.append(newfd)
					WList.append(newfd)
				else:
					rmsg = sd.recv(500)
					if rmsg:
						if (rmsg.decode("ascii")[0] == 'P'):
							roomname, username, userip, userport, mID = decodeResponse(rmsg)
							updateMemberList()
							global msgID
							if(username in roomMemberDict):
								msg = "S:" + str(msgID) + "::\r\n"
								backwardLinkedMemberDict[str(username)] = sd
								messageCounter[str(username)] = int(mID)
								print("Backward link is successfully established")
								sd.sendall(msg.encode("ascii"))
							else:
								sd.close()
						elif (rmsg.decode("ascii")[0] == 'T'):
							roomname, originHID, origin_username, mID, msgLength, content = decodeResponse(rmsg)
							if (roomname == joinedRoomName):
								if(origin_username not in roomMemberDict):
									updateMemberList()
								if(str(origin_username) in messageCounter):
									if(messageCounter[str(origin_username)] != int(mID)):
										messageCounter[str(origin_username)] = int(mID)
										CmdWin.insert(1.0, "\n" +  origin_username + ": " + content)
										forwardMessage(originHID, origin_username, rmsg)
								else:
									messageCounter[str(origin_username)] = int(mID)
									CmdWin.insert(1.0, "\n" +  origin_username + ": " + content)
									forwardMessage(originHID, origin_username, rmsg)
							else:
								print("ERROR: Received message from a person out of the room")
								CmdWin.insert(1.0, "ERROR: Received message from a person out of the room")

						
					else:
						print("A client connection is broken!!")
						WList.remove(sd)
						RList.remove(sd)

					

		# else did not have activity for 10 seconds, 
		# just print out "Idling"
		else:
			print("Server Idling")

def sendMessge(msg):
	if(forwardLinkedMember):
		forwardLinkedMember[1].sendall(msg.encode("ascii"))
	if(backwardLinkedMemberDict):
		for sd in backwardLinkedMemberDict:
			backwardLinkedMemberDict[sd].sendall(msg.encode("ascii"))
	return
def forwardMessage(originHID, origin_username, rmsg):
	if(forwardLinkedMember and forwardLinkedMember[0] != origin_username):
		forwardLinkedMember[1].sendall(rmsg)
	for peer in backwardLinkedMemberDict.items():
		if (peer[0] != str(origin_username)):
			peer[1].sendall(rmsg)

def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	global keepAlive,keep_alive_thread
	keepAlive = False
	#if keep_alive_thread:
	#	keep_alive_thread.join()
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
	global serverPort, serverAddress, myPort
	try:
		serverPort = int(sys.argv[2])
	except:
		serverPort = 32340
	try:
		serverAddress = sys.argv[1]
	except:
		serverAddress = 'localhost'
	try:
		myPort = int(sys.argv[3])
	except:
		myPort = 32341


	win.mainloop()

if __name__ == "__main__":
	main()

