#this function will send a message to a OpenFlow controller

function block_packets(srcIP:addr, destIP:addr, dstPort:port )
		{
	
		system(fmt("python /usr/local/bro/share/bro/policy/martin/cliente.py %s %s %s drop",destIP,dstPort,srcIP));
		print("Msg Sent to controller");#esto lo deveria mandar el programa de python no el BRo
		print fmt(" Address block %s",srcIP);

	    }
