#Project: Client for OpenWeatherMap API
#@author Barbora Nemčeková <xnemce06@stud.fit.vutbr.cz>

import json
import sys
import socket

port = 80
host = "api.openweathermap.org"

if len(sys.argv) != 3:
    print("Incorrect number of arguments")
    sys.exit()
else:    
    key = sys.argv[1]
    city = sys.argv[2]

#create socket
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except Exception as err:
    print ("socket creation failed")
    sys.exit()
    
#connect to remote server
client_socket.connect((host, port))

#send data to remote server 
url = "/data/2.5/weather?q=" + city +"&APPID=" + key +"&units=metric"
request = "GET " + url  +" HTTP/1.1\n" + "Host: " + host +"\r\n\r\n"
req_encode = request.encode("utf-8")

try:
    client_socket.sendall(req_encode)
except Exception as err: 
    print ("send fail")
    sys.exit()

#receive data
reply = client_socket.recv(4096).decode()

if reply.find('HTTP/1.1 200 OK') == 0:

    reply = reply.split('\r\n\r\n')[1]

    data = json.loads(reply)

    print("\nCity: " + data["name"])
    print("Description: " + data["weather"][0]["description"])
    print("Temperature: %.1f" % data["main"]["temp"] + " C")
    print("Humidity: %d" % data["main"]["humidity"] + " %")
    print("Pressure: %d" % data["main"]["pressure"] + " hPa")
    print("Wind speed: %.2f" % data["wind"]["speed"] + " m/s")
    
    if reply.find('deg') == -1:
        print("Wind-deg: -")
    else:
        print("Wind degree: %d" % data["wind"]["deg"])

elif  reply.find('HTTP/1.1 401 Unauthorized') == 0:
    print("Error 401 Unauthorized: Wrong api key.")

elif reply.find('HTTP/1.1 404 Not Found') == 0:
    print("Error 404 Not Found: City was not found.")
else:
    print("Error.")
