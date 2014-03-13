########################################################icmp_echo_request
#Type :	event (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
#Generated for ICMP echo request messages.

#Param c:	The connection record for the corresponding ICMP flow.
#Param icmp:	Additional ICMP-specific information augmenting the standard connection record c.
#Param id:	The echo request identifier.
#Param seq:	The echo request sequence number.
#Param payload:	The message-specific data of the packet payload, i.e., everything after the first 8 bytes of the ICMP header.
###############################################################################################################################

@load martin/flooding

module ICMPflood;


event icmp_echo_request (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
  
     flood_detection(c);
     #print fmt("%s",payload);
	}
