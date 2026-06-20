#!/bin/bash
# this script runs smartshield in docker using the argument given whether it's an interface or a file
# the output of smartshield will be stored in the local output/ dir


if [ -z "$*" ]; then
  echo "Usage: <script> <interface/file>";
  exit 1;
fi

# Declare an empty array to store interface names
interface_list=()

# get all intefaces
for interface in $(ip link show | awk -F': ' '{print $2}' | sed '/lo/d'); do
  interface_list+=("$interface")
done


# Check if first argument is in the list
if [[ " ${interface_list[*]} " == *" ${1} "* ]]; then
  # first arg is an interface
  docker run -it -d --rm --name smartshield --net=host -p 55000:55000 -v $(pwd)/output:/StratosphereLinuxIPS/output -v $(pwd)/config:/StratosphereLinuxIPS/config stratosphereips/smartshield_p2p ./smartshield.py -e 1 -i ${1}
else
  echo "invalid interface."
fi

