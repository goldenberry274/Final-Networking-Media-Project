# Final-Networking-Media-Project

This project is the final project in the Communication Networks course in Ariel University. 

The project is divided into 3 main parts: The first is the paper that the members of this team wrote. The paper is divided into three parts: The first part has answers for techincal questions regarding the material. The second part has summaries of various studies about topics related to netwroking, such as new encryption protocols. The third part has the plots that we generated for the various fields in TCP, TLS and IP headers among others. It also has explenations about these plots.

As requested, the src directory contains the Python file that can generate plots that compare different types of IP, TCP and TLS fields. The res directory contains all the resulting plots from both Wireshark and the Plotgenerator.

Informaiton about the code: The code uses Python 3.12.3. 
Python packaes used for the code: os, matplotlib.pyplot, scapy.layers.inet, scapy.layers.tls.all, scapy.all, datetime, collections, numpy.
To run the code: The code will look for a directory named "Recordings" (One such directory is in the zip file in the Moodle). If there is no such directory it will inform the user and stop. If the code does find the directory, it asks the user to pick a field to plot. Once a filed is picked, it will go through all the pcap or pcapng files and plot out the field. It will then save the plot to a folder named "plots" (If there is no such folder it will be created.) Note that the "Recordings" folder must be in the same level as code.
