
@load martin/flooding

module adaptativeTreshold;

event connection_SYN_packet (c: connection, pkt: SYN_packet)
	{
  
     flood_detection(c);

}
