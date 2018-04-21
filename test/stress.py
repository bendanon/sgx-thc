import os,sys,random

numOfNodes = int(sys.argv[1])
schizzo = len(sys.argv) == 3 and sys.argv[2] == "-s"
startPort = 4441

if schizzo:
	lastNodePort = startPort+1		
else:
	lastNodePort = startPort+numOfNodes-1

fmt="""
{
    "num_of_nodes":%d,
    "port":%d,
    "email":"bendanon@gmail.com",
    "p0":%d,
    "p1":%d,
    "p2":%d,
    "p3":%d,
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
    "email":"bendanon@gmail.com",
    "p0":%d,
    "p1":%d,
    "p2":%d,
    "p3":%d,
    "neighbors":
    [
        {"ip":"127.0.0.1", "port":%d}
    ]
}
"""

fileNameFmt='config_%d.json'

def r():
	return random.randrange(255)

#Create edge nodes - first and last
filename = fileNameFmt % (startPort)
f = open(filename, 'w')
f.write(edgeFmt % (numOfNodes, startPort,r(),r(),r(),r(),startPort+1))

filename = fileNameFmt % (lastNodePort)
f = open(filename, 'w')
f.write(edgeFmt % (numOfNodes, lastNodePort, r(),r(),r(),r(),lastNodePort-1))


if not schizzo:
	
	for currPort in range(startPort+1, lastNodePort):
		filename = fileNameFmt % (currPort)
		f = open(filename, 'w')
		f.write(fmt % (numOfNodes, currPort, r(),r(),r(),r(), currPort-1, currPort+1))


for i in range(startPort, lastNodePort+1):
	#print "./app config_" + str(i) + ".json"
	os.system("./app config_" + str(i) + ".json output_" + str(i) + ".json &")


