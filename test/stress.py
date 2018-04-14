import os,sys;

numOfNodes = int(sys.argv[1])
schizzo = len(sys.argv) == 3 and int(sys.argv[2]) == "-s"
startPort = 4441

if schizzo:
	lastNodePort = startPort+1		
else:
	lastNodePort = startPort+numOfNodes-1

fmt="""
{
    "num_of_nodes":%d,
    "port":%d,
    "neighbors":
    [
        {"ip":"127.0.0.1", "port":%d},
	{"ip":"127.0.0.1", "port":%d}
    ]
}
"""

edgeFmt="""
{
    "num_of_nodes":%d,
    "port":%d,
    "neighbors":
    [
        {"ip":"127.0.0.1", "port":%d}
    ]
}
"""

fileNameFmt='config_%d.json'


#Create edge nodes - first and last
filename = fileNameFmt % (startPort)
f = open(filename, 'w')
f.write(edgeFmt % (numOfNodes, startPort, startPort+1))

filename = fileNameFmt % (lastNodePort)
f = open(filename, 'w')
f.write(edgeFmt % (numOfNodes, lastNodePort, lastNodePort-1))


if not schizzo:
	
	for currPort in range(startPort+1, lastNodePort):
		filename = fileNameFmt % (currPort)
		f = open(filename, 'w')
		f.write(fmt % (numOfNodes, currPort, currPort-1, currPort+1))


for i in range(startPort, lastNodePort+1):
	#print "./app config_" + str(i) + ".json"
	os.system("./app config_" + str(i) + ".json &")


