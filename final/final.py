# 03/06/2020:	  Anti-forensic tool ----- File(s) in a usb drive or sd card. 
# 03/06/2020:	  detect the drive and provide several options. (1) deep format drive (2) delete a file (3) apply self-destrcution file 
# 03/06/2020:	  Stage 1: fat system. Stage 2: NTFS system. Stage 3: other systems
# 03/06/2020:	  Goals: The target file(s) cannot be recovered by any method.
# 03/06/2020:	   Write 00 to offsets related to the search file or hard drive.
# 03/06/2020:	  Remove any evidence related to the search file had exsit before.
# 03/07/2020:	  MBR ONLY, so maximum partitions = 4.
import sys
import os
import hashlib
import binascii
import partitionID
from ctypes import *
import ctypes
import string
from sys import platform
flag_win = "win32"
flag_linux = "linux"
flag_fbsd = "freebsd"
DriveCounter = 0
noOfDriveSize = 13
possible_drives = [
	r"\\.\PhysicalDrive0", # Windows
	r"\\.\PhysicalDrive1", 
	r"\\.\PhysicalDrive2",
	r"\\.\PhysicalDrive3",
	"/dev/mmcblk0", # Linux - MMC
	"/dev/mmcblk1",
	"/dev/mmcblk2",
	"/dev/sda", # Linux - Disk
	"/dev/sdb",
	"/dev/sdc",
	"/dev/disk1", #MacOSX
	"/dev/disk2",
	"/dev/disk3",
]

def logo():
	print("                                                    __----~~~~~~~~~~~------___")
	print("                                   .  .   ~~//====......          __--~ ~~    ")
	print("                   -.            \_|//     |||\\  ~~~~~~::::... /~            ")
	print("                ___-==_       _-~o~  \/    |||  \\            _/~~-           ")
	print("        __---~~~.==~||\=_    -_--~/_-~|-   |\\   \\        _/~                ")
	print("    _-~~     .=~    |  \\-_    '-~7  /-   /  ||    \      /                   ")
	print("  .~       .~       |   \\ -_    /  /-   /   ||      \   /                    ")
	print(" /  ____  /         |     \\ ~-_/  /|- _/   .||       \ /                     ")
	print(" |~~    ~~|--~~~~--_ \     ~==-/   | \~--===~~        .\                      ")
	print("          '         ~-|      /|    |-~\~~       __--~~                        ")
	print("                      |-~~-_/ |    |   ~\_   _-~            /\                ")
	print("                           /  \     \__   \/~                \__              ")
	print("                       _--~ _/ | .-~~____--~-/                  ~~==.         ")
	print("                      ((->/~   '.|||' -_|    ~~-/ ,              . _||        ")
	print("                                 -_     ~\      ~~---l__i__i__i--~~_/         ")
	print("                                 _-~-__   ~)  \--______________--~~           ")
	print("                               //.-~~~-~_--~- |-------~~~~~~~~                ")
	print("                                      //.-~~~--\                              ")
	print("-------------------INFR 4690U FINAL PROJECT --TONY WANG --100474399-----------")
	print("------The Anti-forensics tool. Different tasks available are below:-----------")

# The function to read and get the total number of physical drives of the pc 

def extractMBR(no = 0, flag = ""):
		for drive in possible_drives:
			try:
				with open(possible_drives[no], 'rb') as fp:
					if (sys.platform.startswith(flag_win)):
						hex_list = ["{:02x}".format(c) for c in fp.read(512)]
					elif sys.platform.startswith(flag_linux):
						hex_list = ["{:02x}".format(ord(c)) for c in fp.read(512)]
				if (flag == "load"):
					global DriveCounter
					DriveCounter = DriveCounter + 1
					print ("")
					print ("-------------------" + possible_drives[no] +" with the following partition(s) is found")
				fp.close();
				return hex_list
			except:
				pass

# The function to load the page
def platform():
	maxPhysicalDrives = DriveCounter

	if sys.platform.startswith(flag_fbsd):
		os = "freeBSD"
	elif sys.platform.startswith(flag_linux):
		os = "Linux"
	elif sys.platform.startswith(flag_win):
		os = "Windows"

	print ("")
	print ("-------------------Your current operating system is -------- " + os)

	for x in range(noOfDriveSize):
		try:
			parseMBRInfo(extractMBR(x,"load"),x)
			parseInfo(extractMBR(x,""),x)	
		except:
			pass

# The function to get each logical drives detailed information
def get_drives_details():
	drives = []
	bitmask = ctypes.windll.kernel32.GetLogicalDrives()
	for letter in string.ascii_uppercase:
		if bitmask & 1:
			drives.append(letter)
		bitmask >>= 1
		kernel32 = ctypes.windll.kernel32

	volumeNameBuffer = ctypes.create_unicode_buffer(1024)
	fileSystemNameBuffer = ctypes.create_unicode_buffer(1024)
	serial_number = None
	max_component_length = None
	file_system_flags = None

	for drive in drives:
		bitmask = ctypes.windll.kernel32.GetVolumeInformationW(
		ctypes.c_wchar_p(drive + ":\\"),
		volumeNameBuffer,
		ctypes.sizeof(volumeNameBuffer),
		serial_number,
		max_component_length,
		file_system_flags,
		fileSystemNameBuffer,
		ctypes.sizeof(fileSystemNameBuffer)
		)
		print ("------Logical HardDrive " + drive + ":\\")
		print ("	  Drive Name:       " + str(volumeNameBuffer.value))
		print ("	  Drive Type:       " + str(fileSystemNameBuffer.value))
		print ("--------------------------------")
	return drives

# the function to extract the partition info from the target pysical hard drive
def saveData(FATS,FATE,no):
	try:
		with open(possible_drives[no], 'rb') as fp:
			fp.seek(FATS)
			if (sys.platform.startswith(flag_win)):
				hex_list = ["{:02x}".format(c) for c in fp.read(FATE)]
			elif sys.platform.startswith(flag_linux):
				hex_list = ["{:02x}".format(ord(c)) for c in fp.read(FATE)]
		fp.close()
		return hex_list
	except:
		pass
# The function to check if mbr info is found from the physical hard drive
def checkSignature(rawData):
	if (rawData[511] == "aa" and rawData[510] == "55" and rawData[444] == "00" and rawData[445] == "00" or rawData[444] == "5a" or rawData[445] == "5a"):
		print("MBR found on Sector 0")
		return True
	else:
		print("MBR signatures doesn't match (MBR may not present)")
		return False

# The function to check the mbr type
def parseMBRInfo(rawData,noOfPartition):
	try:
		if (checkSignature(rawData) != True):
			exit
		print ("Disk Signature:" +rawData[443] + rawData[442] + rawData[441] +rawData[440])
		print("Possible MBR scheme", end == ':')
		if (rawData[218] == "00" and rawData[219] == "00"):
			print(" Modern standard MBR found.")
		elif (rawData[428] == "78" and rawData[429] == "56"):
			print (" Advanced Active Partitions (AAP) MBR found")
		elif (rawData[0] == "eb" and rawData[2] == "4e" and rawData[3] == "45" and rawData[4] == "57" and rawData[6] == "4c" and raw_input[7] == "44" and rawData[8] == "52"):
			print (" NEWLDR MBR found.")
		elif (rawData[380] == "5a" and rawData[381] == "a5"):
			print (" MS-DOS MBR found.")
		elif (rawData[252] == "aa" and rawData[253] == "55"):
			print (" Disk Manager MBR")
		else:
			print (" Generic MBR found")
	except:
		pass

def parseInfo(rawData,noOfPartition):	

	# 1MB = 1024 * 1024 B
	CalFormula = 1048576
	# MBR
	maxPartitionMBR = 4
	#	         0   1   2   3   4   5   6   7   8	 9   10  11  12  13  14  15
	partion = [[446,447,448,449,450,451,452,453,454,455,456,457,458,459,460,461],
			   [462,463,464,465,466,467,468,469,470,471,472,473,474,475,476,477],
			   [478,479,480,481,482,483,484,485,486,487,488,489,490,491,492,493],
			   [494,495,496,497,498,499,500,501,502,503,504,505,506,507,508,509],
			   [444,445,510,511,512]]
	for x in range(maxPartitionMBR):
		try:
			if ((rawData[partion[x][0]] == "00" or rawData[partion[x][0]] == "80") and (rawData[partion[x][1]] != "00" 
				or rawData[partion[x][2]] != "00" or rawData[partion[x][3]] !="00") and rawData[partion[x][4]] != "00"):
				print ("")
				print ("---------------------------  " + str(x + 1) + "st Partition found   ---------------------------")
				# The reference from https://github.com/shubham0d/MBR-extractor
				partitionTypes = partitionID.partitionIdList(rawData[partion[x][4]])
				partitionStartSector = int(rawData[partion[x][11]] + rawData[partion[x][10]] + rawData[partion[x][9]] + rawData[partion[x][8]], 16)
				partitionEndSector = int(rawData[partion[x][15]] + rawData[partion[x][14]] + rawData[partion[x][13]] + rawData[partion[x][12]], 16)
				print ("Partition type:       "+ partitionTypes)
				print ("")
				noOfSectors = int(rawData[partion[x][15]] + rawData[partion[x][14]] + rawData[partion[x][13]] + rawData[partion[x][12]], 16)
				totalSizeInByte = ((partitionStartSector+noOfSectors) * 512)-(partitionStartSector * 512)
				print ("Total partition size:					     "+ str(totalSizeInByte/CalFormula) + " MB")
				## call the function if the current partition type is FAT32
				if (rawData[partion[x][4]] == "0b" or rawData[partion[x][4]] == "0c"):
					FAT32Ana(saveData((partitionStartSector*512),512,noOfPartition),x+1)
				if (rawData[partion[x][4]] == "07"):
					NTFSAna(saveData((partitionStartSector*512),512,noOfPartition),x+1)
		except:
			pass

# FAT function to extract partition boot sector from the FAT32 partition
def FAT32Ana(rawData,no): 
	global sectorSize
	global clusterSector
	global clusterSize
	global fileDirectoryStartSector
	global firstClusterOfRootDirectory
	sectorSize = int(rawData[12] + rawData[11], 16)	
	reservedArea = int(rawData[15] + rawData[14], 16)
	clusterSector = int(rawData[13], 16)
	clusterSize = clusterSector * sectorSize
	noOfFAT = int(rawData[16], 16)
	FATSize = int(rawData[39] + rawData[38] + rawData[37] + rawData[36], 16)
	firstClusterOfRootDirectory = int(rawData[47] + rawData[46] + rawData[45] + rawData[44], 16)
	minNoCluster = pow(2,1) 
	print ("Each sector size:                                            " + str(sectorSize))
	print ("Cluster per sector:                                          " + str(clusterSector))
	print ("Reserved area:                                               " + str(reservedArea))
	print ("Total file allocation number:                                " + str(noOfFAT))
	for x in range(noOfFAT):
		print ("FAT " + str(x) + " Start sector: " + str(reservedArea + (x * FATSize)) + " End sector: " + str(reservedArea + ((x+1) * FATSize)-1))
	print ("Cluster size in bytes of the current FAT partition is:       " + str(clusterSize))
	print ("The smallest cluster number of the current FAT partition is: " + str(minNoCluster))
	print ("\n\n")
	if (noOfFAT == 2):
		fileDirectoryStartSector = (reservedArea + (FATSize * 2))
		fileDirectoryStartSectorinBytes = (reservedArea + (FATSize * 2)) * 512
	else:
		print ("Number of FAT is incorrect.")

def NTFSAna(rawData,no): 
	global NTFS_MFT_LocationInt
	sectorSize = int(rawData[12] + rawData[11], 16)	
	clusterSector = int(rawData[13], 16)
	clusterSize = clusterSector * sectorSize
	MFT_Entry = 35
	MFTSize = 1024 # NTFS default 
	volumeSerialNo_1 = str.upper(rawData[75] + rawData[74])
	volumeSerialNo_2 = str.upper(rawData[73] + rawData[72])
	NTFS_MFT_LocationInt = ((int(rawData[55] + rawData[54] + rawData[53] + rawData[52] + rawData[51] + rawData[50] + rawData[49] + rawData[48],16)) * clusterSize)
	MFT_StartCluster = int(NTFS_MFT_LocationInt / clusterSize)
	MFT_Location = MFT_StartCluster * clusterSize
	print ("The volume serial number of partition " + str(no) + " is:                  " + volumeSerialNo_1 + " - " + volumeSerialNo_2)
	print ("Cluster size in bytes of the current NTFS partition:         " + str(clusterSize))
	print ("The first cluster of the MFT is:                             " + str(MFT_StartCluster))
	print ("The size of each Master File Table entry in bytes is:        " + str(MFTSize))

def myFmtCallback(command, modifier, arg):
    print("------Formatting in process...")
    return 1    # TRUE

# Securely format the hard drive under Windows System
# Support FAT32, NTFS, FAT
def format_drive(Drive, Format, Title):
	if (sys.platform.startswith(flag_win)):
		print("------Starting Low-Level Formating Process....\n------The Process may take several hours depends on the Hard Drive Volume Size.")
		fm = ctypes.windll.LoadLibrary('fmifs.dll')
		FMT_CB_FUNC = WINFUNCTYPE(c_int, c_int, c_int, c_void_p)
		FMIFS_HARDDISK = 0x0B
		fm.FormatEx(c_wchar_p(Drive), FMIFS_HARDDISK, c_wchar_p(Format),
					c_wchar_p(Title), True, c_int(0), FMT_CB_FUNC(myFmtCallback))
		print ("------Process completed.")
		print ("\n\n")
	else:
		print ("------The Operating System must be Windows only.")

# perform the formating process
def win_format():
	win_format = ["NTFS", "FAT32", "FAT"]
	drives = []
	bitmask = ctypes.windll.kernel32.GetLogicalDrives()
	for letter in string.ascii_uppercase:
		if bitmask & 1:
			drives.append(letter)
		bitmask >>= 1
	print ("\n\n")
	print ("-------------------Format HardDrives in Windows-------------------------------")
	print ("------The Current Operating System should be Windows Only.")
	print ("	  The Process will Delete Everything Permanetly on the Target Drive.")
	print ("	  The User Should Pay Attention to each Step.")
	print ("	  Press R(r) to go back to the previous menu.\n")
	get_drives_details()
	while True:
		driveNo = input("      Select a Drive [Ex. F] to do the low-level format: ")
		if (driveNo == 'r' or driveNo == 'R'):
			print("      Go back to the previous menu....")
			os.system('cls')
			break
		elif (driveNo.upper() in drives):
			print ("------The Target Drvie letter is set to: " + driveNo.upper() + ":\\")
			print ("------Available Drive Format: ")
			for x in range(len(win_format)):
				print ("	  Press " + str(x) + " for " + win_format[x])
			try:
				driveFormat = int(input("      Select a New Hard Drive Type you want to Implement: "))
				if (driveFormat == 0 or driveFormat == 1 or driveFormat == 2):
					print("------The Target Drvie Format is set to: " + win_format[driveFormat])
					driveName = input("      Please Type a New Name for the Drive: ")
					if (driveName == None):
						print ("Drive Name cannot be null")
					else:
						print("------The Target Drvie Name is set to: " + driveName)
						option = input("      Type 'YES' to Perform the Formatting ")
						if (option == "YES" or option == "yes"):
							format_drive(driveNo.upper() + ":\\", win_format[driveFormat], driveName)
							break
						else:
							print ("The Task is Cancelled.")
							os.system('cls')
							break
				else:
					print("      Please select an available drive format....")
			except:
				print("      Something wrong. Please try again....")
		else:
			print("      Please select an available drive letter....")



if __name__ == '__main__':
	tasks = {
	1: platform,
	2: win_format,
}
	while True:
		logo()
		print("\n------Press 1 to Display all Physical & Logical HardDrive(s) Information\n------Press 2 to Format HardDrives in Windows\n------Press 3 to Format HardDrives in Linux\n------Press 0 to exit")
		try:
			number = int(input("      Select task number you want to implement: "))
			if number == 0:
				print("      Exiting the program....")
				break
			elif number not in tasks:
				print("      Invalid Input. Please try again....")
				continue
			else:
				print()
				tasks[number]()
		except:
			print("      Something wrong. Please try again....")
			pass
