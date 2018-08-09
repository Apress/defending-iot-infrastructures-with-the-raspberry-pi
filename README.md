# Apress Source Code



This repository accompanies [*Defending IoT Infrastructures with the Raspberry Pi*](http://www.apress.com/9781484236994) by Chet Hosmer (Apress, 2018).



[comment]: #cover

![Cover image](9781484236994.jpg)



Download the files as a zip using the green button, or clone the repository to your machine using Git.



## Releases



Release v1.0 corresponds to the code in the published book, without corrections or updates.



## Contributions



See the file Contributing.md for more information on how you can contribute to this repository.


## Quick Start

Assumptions: Raspberry Pi Desktop is: /home/pi/Desktop

1. Copy the CONTENTS of the BINARIES folder to the Desktop of your Raspberry Pi
2. Verify the desktop launcher
   You will need to change the Exec and Path lines if your default user is not pi
  [Desktop Entry]
  
Name=piSensorGUI
Icon=gnome-monitor
  
Exec=sudo /home/pi/Desktop/SENSOR/piSensor
  TType=Application
  
Terminal=False

  Path=/home/pi/Desktop/SENSOR
  
GenericName=Raspberry Pi Passive Network Sensor
3. Verify that the executable piSensor 
   cd /home/pi/SENSOR
   chmod +x piSensor

This should produce an icon on your desktop, then double click to start.

Source Code: Requirements
1) Python 2.7.13 is properly installed
2) 3rd Party Libraries Required are:
   sudo pip install netaddr
   sudo pip install pygeoip
3) Copy the ENTIRE Source Folder a desired location.  i.e. /home/pi/Desktop/

The Source Code Folder contains two source files

piSensor.py
rpt.py

To execute the script open a terminal window

cd /home/pi/Desktop/SOURCE
sudo python piSensor.py
