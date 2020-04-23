# Demo Simulation of Apple's "Find My" System

By Hannah Huang and Warren Partridge

## Overview

The code in `findmy.py` performs a simple simulation of Apple's Find My system in a scenario where Bob loses his phone in an airport without internet. Bob's phone uses Bluetooth to communicate with nearby iDevices and have them relay approximate location information to iCloud.

For the sake of simplicity, our demo doesn't actually perform network or Bluetooth calls. Docstrings in the code indicate where this is the case.

## To run this code

1. Install the necessary packages without failing on packages you have earlier versions of by running `cat requirements.txt | xargs -n 1 pip3 install`
2. Run `python3 findmy.py`
3. Watch the simulation!
