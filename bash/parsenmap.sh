#!/bin/bash
#title:		parsenmap.sh
#author:	Marrion, Taylor
#date:		20190214
#purpose:	This script will read Nmap network scan results saved to a .txt file and summarize usage of services.


#decalre input and output path variables
input="/home/teebs/Desktop/NMAP_all_hosts.txt"
output="/home/teebs/Desktop/Parse_NMAP.txt"


#Readability
echo "Showing results of:" > $output
egrep "Nmap 6.47.*+$" $input >> $output
echo "" >> $output


echo "---------- 1. Counts of each service running ----------" >> $output
echo "" >> $output

#egrep for "PORT STATE SERVICE" lines, isolate 3rd field, sort alphabetically, count instances of unique strings and remove duplicates, sort numerically high-to-low
egrep "^[0-9]+/(tcp|udp)\s+open\s+[a-zA-Z0-9\-]+$" $input | awk '{print $3}' | sort | uniq -c | sort -nr >> $output
echo "" >> $output


echo "---------- 2. IP addresses using each open service ----------" >> $output
echo "" >> $output

#create array of service names, sorted by highest count of use
mapfile -t svc_array < <(egrep "^[0-9]+/(tcp|udp)\s+open\s+[a-zA-Z0-9\-]+$" $input | awk '{print $3}' | sort | uniq -c | sort -nr | awk '{print $2}')

#create array of sorted, unique IP addresses
mapfile -t IP_array < <(egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}$" $input | sort -u)

#loop through svc_array to list service names
for svc in "${svc_array[@]}"
do
echo $svc >> $output
echo "====================" >> $output
	#loop through IP_array
	for IP in "${IP_array[@]}"
	do
	str="Nmap scan report for "$IP
	# awk will search using start and end string patterns to create blocks of text for reliable parsing for any number of open ports
	x=$(cat $input | awk "/$str/, /MAC/" | egrep "^[0-9]+/(tcp|udp)\s+open\s+"$svc"$" | wc -l)
		#if current svc is found to be running, echo the current IP
		if (( $x >= 1 ))
		then
		echo $IP >> $output
		fi
	done
echo ""  >> $output
done

#end

