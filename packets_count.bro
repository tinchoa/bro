#this function counts the packets for every address and return the number of packets

function packets_count(address : vector of addr,endereco:addr) : int
        {
        local k=0;#indice de address
        #local temp:addr; #temporario para almacenar o endereço
        local addition=0;# vector
    
        for (k in address)
        	{
        	if(endereco == address[k])
        		{
        		++addition;
        		#print("hola");
        		}
        	}
      #  print fmt ("Address %s Packests %d",endereco,addition);
return addition;
        }
