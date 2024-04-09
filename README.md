Instructionns to run the code -

1. Change the interface macro value in both simDNSclient.c and simDNSserver.c depending on which interface you are using ensure both interfaces are same.
2. Run the makefile - makfile all
3. 2 binaries will be generated client and server.
4. Enter the destination mac address to whom you want send (keep it same as source address for loopback).
5. Query the domain whose IP you want on the client side in the way as follows -
   * Usage: getIP `<N>` `<domain1>` `<domain2>` ... `<domainN>`
6. You will receive the response if the message is not dropped.
7. To change the probablity to drop the message there is MACRO in simDNSserver.c named p which is needs to be changed accordingly.
