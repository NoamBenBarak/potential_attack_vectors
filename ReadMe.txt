------------

Description
------------
The "Noam" service provides customers the ability to understand the potential attack
vectors risking their cloud data centers. 
This is a service that a customer can query and get the attack surface of a VM -
meaning which other virtual machines in the account can access and attack it.
There are two REST endpoints:
/attack- gets a vm_id as a query parameter and return a JSON list of the
virtual machine ids that can potentially attack it.
/stats- return service statistics in a JSON format.

Noam exc. uses the 'http://localhost/api/v1/' URL (attack/stats).
The input for the service is a JSON document describing the cloud environment of a customer.
A cloud environment is described using 2 types of objects: VMs and firewall rules.

Environment
--------------
The code run on Linux operating system.
and uses python 3


Install Dependencies
-----------------------
Install the dependencies and compile the file:
install python3-pip
pip install flask


Runing the server
-------------------
sudo python Exc_NoamBenBarak.py <input-file-name>
 




