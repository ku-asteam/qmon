# Qmon
Switch Queue Monitoring Module for Web Applications

## Introduction

Qmon is to monitor queue length of ports at the egress pipeline and deliver the information to the ingress pipeline in RMT switches.
This enables the switch to perform various network fucnctions that require congestion information at the ingress pipeline.

## Requirements and Dependencies

* Barefoort Tofino switches
* Barefoot Tofino SDE 9.2.0+
* Python 2.7+

## Instructions

* Compile qmon.p4 using P4C compiler (Please use p4_build.sh provided by SDE)
* Run the compiled qmon program using SDE shell scripts (i.e., run_switchd.sh) and configure port information
* Run the contoller (con.py) using python command 'python con.py'
* Generate packets that pass though the switch, and you can see that the queue length information is printed by the controller
